//! Contract tests for `SkillContextService` and related types.
//!
//! Covers: no skills, skill unavailable, missing/denied trust, hidden capability,
//! deterministic ordering/rebuild, and redaction of non-model-safe metadata.

use ironclaw_turns::run_profile::{
    InstalledSkillSnapshot, NoopSkillContextSource, SkillContextError, SkillContextService,
    SkillContextSource, SkillRunSnapshot, SkillTrustLevel, SkillVisibility,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn visible_trusted(name: &str, description: &str, prompt: &str) -> InstalledSkillSnapshot {
    InstalledSkillSnapshot {
        name: name.to_string(),
        trust: SkillTrustLevel::Trusted,
        visibility: SkillVisibility::Visible,
        prompt_content: Some(prompt.to_string()),
        safe_description: description.to_string(),
        ordering_key: name.to_string(),
    }
}

fn visible_installed(name: &str, description: &str) -> InstalledSkillSnapshot {
    InstalledSkillSnapshot {
        name: name.to_string(),
        trust: SkillTrustLevel::Installed,
        visibility: SkillVisibility::Visible,
        prompt_content: Some("secret prompt".to_string()),
        safe_description: description.to_string(),
        ordering_key: name.to_string(),
    }
}

fn hidden_skill(name: &str) -> InstalledSkillSnapshot {
    InstalledSkillSnapshot {
        name: name.to_string(),
        trust: SkillTrustLevel::Trusted,
        visibility: SkillVisibility::Hidden,
        prompt_content: Some("hidden prompt".to_string()),
        safe_description: "hidden description".to_string(),
        ordering_key: name.to_string(),
    }
}

fn denied_skill(name: &str) -> InstalledSkillSnapshot {
    InstalledSkillSnapshot {
        name: name.to_string(),
        trust: SkillTrustLevel::Trusted,
        visibility: SkillVisibility::Denied,
        prompt_content: Some("denied prompt".to_string()),
        safe_description: "denied description".to_string(),
        ordering_key: name.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_skills_produces_empty_ok() {
    let snapshot = SkillRunSnapshot::empty();
    let service = SkillContextService::new(snapshot.clone());
    let result = service.skill_snippets(&snapshot).await;
    assert_eq!(result.unwrap(), vec![]);
}

#[tokio::test]
async fn all_hidden_or_denied_produces_empty_ok() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        hidden_skill("alpha"),
        denied_skill("beta"),
        hidden_skill("gamma"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let result = service.skill_snippets(&snapshot).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn missing_trust_data_fails_closed() {
    let snapshot = SkillRunSnapshot {
        entries: vec![visible_trusted("alpha", "desc", "prompt")],
        snapshot_version: String::new(), // empty = missing
    };
    let service = SkillContextService::new(snapshot.clone());
    let err = service.skill_snippets(&snapshot).await.unwrap_err();
    assert_eq!(err, SkillContextError::TrustDataMissing);
}

#[tokio::test]
async fn denied_visibility_never_in_output() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        visible_trusted("alpha", "visible skill", "prompt"),
        denied_skill("beta"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    assert_eq!(snippets.len(), 1);
    assert_eq!(snippets[0].snippet_ref, "skill:alpha");
    assert!(!snippets[0].safe_summary.contains("denied"));
}

#[tokio::test]
async fn hidden_visibility_never_in_output() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        visible_trusted("alpha", "visible skill", "prompt"),
        hidden_skill("beta"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    assert_eq!(snippets.len(), 1);
    assert_eq!(snippets[0].snippet_ref, "skill:alpha");
    assert!(!snippets[0].safe_summary.contains("hidden"));
}

#[tokio::test]
async fn trusted_skill_includes_prompt_content() {
    let snapshot = SkillRunSnapshot::from_entries(vec![visible_trusted(
        "alpha",
        "the description",
        "the prompt content",
    )]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    assert_eq!(snippets.len(), 1);
    assert!(snippets[0].safe_summary.contains("the description"));
    assert!(snippets[0].safe_summary.contains("the prompt content"));
}

#[tokio::test]
async fn installed_skill_excludes_prompt_content() {
    let snapshot =
        SkillRunSnapshot::from_entries(vec![visible_installed("alpha", "the description")]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    assert_eq!(snippets.len(), 1);
    assert!(snippets[0].safe_summary.contains("the description"));
    assert!(
        !snippets[0].safe_summary.contains("secret prompt"),
        "installed skill must not expose prompt content"
    );
}

#[tokio::test]
async fn deterministic_ordering_same_snapshot() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        visible_trusted("charlie", "desc c", "prompt c"),
        visible_trusted("alpha", "desc a", "prompt a"),
        visible_trusted("bravo", "desc b", "prompt b"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let first = service.skill_snippets(&snapshot).await.unwrap();
    let second = service.skill_snippets(&snapshot).await.unwrap();
    assert_eq!(first, second, "same snapshot must produce byte-equal output");
    // Verify sorted order
    let names: Vec<&str> = first.iter().map(|s| s.snippet_ref.as_str()).collect();
    assert_eq!(names, vec!["skill:alpha", "skill:bravo", "skill:charlie"]);
}

#[tokio::test]
async fn deterministic_ordering_shuffled_input() {
    let entries_a = vec![
        visible_trusted("charlie", "desc c", "prompt c"),
        visible_trusted("alpha", "desc a", "prompt a"),
        visible_trusted("bravo", "desc b", "prompt b"),
    ];
    let entries_b = vec![
        visible_trusted("bravo", "desc b", "prompt b"),
        visible_trusted("charlie", "desc c", "prompt c"),
        visible_trusted("alpha", "desc a", "prompt a"),
    ];
    let snap_a = SkillRunSnapshot::from_entries(entries_a);
    let snap_b = SkillRunSnapshot::from_entries(entries_b);

    let service_a = SkillContextService::new(snap_a.clone());
    let service_b = SkillContextService::new(snap_b.clone());

    let output_a = service_a.skill_snippets(&snap_a).await.unwrap();
    let output_b = service_b.skill_snippets(&snap_b).await.unwrap();
    assert_eq!(output_a, output_b, "insertion order must not affect output");
}

#[tokio::test]
async fn snapshot_version_determinism() {
    let entries_a = vec![
        visible_trusted("charlie", "desc c", "prompt c"),
        visible_trusted("alpha", "desc a", "prompt a"),
    ];
    let entries_b = vec![
        visible_trusted("alpha", "desc a", "prompt a"),
        visible_trusted("charlie", "desc c", "prompt c"),
    ];
    let snap_a = SkillRunSnapshot::from_entries(entries_a);
    let snap_b = SkillRunSnapshot::from_entries(entries_b);
    assert_eq!(
        snap_a.snapshot_version, snap_b.snapshot_version,
        "same entries in different order must produce the same version"
    );
}

#[tokio::test]
async fn redaction_no_raw_paths_or_internals() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        visible_trusted("alpha", "A helpful skill", "Use this skill to help"),
        visible_installed("beta", "Another helpful skill"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    for snippet in &snippets {
        // No file paths
        assert!(
            !snippet.safe_summary.contains('/'),
            "must not contain file path separators"
        );
        assert!(
            !snippet.safe_summary.contains('\\'),
            "must not contain file path separators"
        );
        // No capability IDs (would look like UUIDs or structured IDs)
        assert!(
            !snippet.safe_summary.contains("cap_"),
            "must not contain capability IDs"
        );
        // No secret handles
        assert!(
            !snippet.safe_summary.contains("secret"),
            "must not contain secret handles"
        );
        // Only contains description/prompt content
        assert!(
            snippet.safe_summary.contains("helpful skill")
                || snippet.safe_summary.contains("Use this skill"),
            "must contain only model-safe content"
        );
    }
}

#[tokio::test]
async fn noop_skill_context_source_returns_empty() {
    let noop = NoopSkillContextSource;
    let snapshot = SkillRunSnapshot::from_entries(vec![visible_trusted(
        "alpha",
        "desc",
        "prompt",
    )]);
    let result = noop.skill_snippets(&snapshot).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn mixed_visibility_correct_filtering() {
    let snapshot = SkillRunSnapshot::from_entries(vec![
        visible_trusted("alpha", "trusted visible", "trusted prompt"),
        visible_installed("beta", "installed visible"),
        hidden_skill("gamma"),
        denied_skill("delta"),
    ]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();

    // Only visible entries appear
    assert_eq!(snippets.len(), 2);

    // Trusted includes prompt
    let alpha = snippets.iter().find(|s| s.snippet_ref == "skill:alpha").unwrap();
    assert!(alpha.safe_summary.contains("trusted visible"));
    assert!(alpha.safe_summary.contains("trusted prompt"));

    // Installed excludes prompt
    let beta = snippets.iter().find(|s| s.snippet_ref == "skill:beta").unwrap();
    assert!(beta.safe_summary.contains("installed visible"));
    assert!(
        !beta.safe_summary.contains("secret prompt"),
        "installed skill must not expose prompt content"
    );

    // Hidden and denied are absent
    let refs: Vec<&str> = snippets.iter().map(|s| s.snippet_ref.as_str()).collect();
    assert!(!refs.contains(&"skill:gamma"));
    assert!(!refs.contains(&"skill:delta"));
}

#[tokio::test]
async fn into_loop_snippet_conversion() {
    use ironclaw_turns::run_profile::LoopContextSnippet;

    let snapshot = SkillRunSnapshot::from_entries(vec![visible_trusted(
        "alpha",
        "desc",
        "prompt",
    )]);
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service.skill_snippets(&snapshot).await.unwrap();
    let loop_snippet: LoopContextSnippet = snippets.into_iter().next().unwrap().into_loop_snippet();
    assert_eq!(loop_snippet.snippet_ref, "skill:alpha");
    assert!(loop_snippet.safe_summary.contains("desc"));
}
