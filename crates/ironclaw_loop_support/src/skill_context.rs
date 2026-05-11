use async_trait::async_trait;
use ironclaw_skills::{ParsedSkill, SkillTrust, parse_skill_md};
use ironclaw_turns::{
    LoopMessageRef,
    run_profile::{
        AgentLoopHostError, AgentLoopHostErrorKind, InstalledSkillSnapshot, LoopContextSnippet,
        LoopRunContext, SkillContextError, SkillContextService, SkillContextSource,
        SkillRunSnapshot, SkillTrustLevel, SkillVisibility,
    },
};
use thiserror::Error;

/// Host-owned source for production skill context candidates.
///
/// Implementations own storage/policy lookups. This trait intentionally returns
/// host-approved trust/visibility decisions plus raw SKILL.md content only for
/// visible candidates so `ironclaw_turns` remains a snapshot-only loop boundary.
#[async_trait]
pub trait HostSkillContextSource: Send + Sync {
    async fn load_skill_context_candidates(
        &self,
        run_context: &LoopRunContext,
    ) -> Result<Vec<HostSkillContextCandidate>, HostSkillContextBuildError>;
}

/// One host-approved skill candidate before parsing and snapshot conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSkillContextCandidate {
    /// Raw SKILL.md content from the production skill source.
    ///
    /// Hidden/denied candidates may omit raw content; they are policy-filtered
    /// before parsing so invisible skills cannot fail prompt construction via
    /// malformed prompt files.
    pub skill_md: Option<String>,
    /// Host-approved trust state. `None` fails the build closed.
    pub trust: Option<SkillTrust>,
    /// Host-approved model visibility. `None` fails the build closed.
    pub visibility: Option<SkillVisibility>,
    /// Optional deterministic ordering key. Defaults to parsed skill name.
    pub ordering_key: Option<String>,
}

impl HostSkillContextCandidate {
    pub fn new(
        skill_md: impl Into<String>,
        trust: Option<SkillTrust>,
        visibility: Option<SkillVisibility>,
    ) -> Self {
        Self {
            skill_md: Some(skill_md.into()),
            trust,
            visibility,
            ordering_key: None,
        }
    }

    pub fn unavailable(trust: Option<SkillTrust>, visibility: Option<SkillVisibility>) -> Self {
        Self {
            skill_md: None,
            trust,
            visibility,
            ordering_key: None,
        }
    }

    pub fn with_ordering_key(mut self, ordering_key: impl Into<String>) -> Self {
        self.ordering_key = Some(ordering_key.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostSkillContextBuildError {
    #[error("skill context source unavailable")]
    SourceUnavailable,
    #[error("skill context parse failed")]
    ParseFailed,
    #[error("skill context trust data missing")]
    TrustDataMissing,
    #[error("skill context visibility data missing")]
    VisibilityDataMissing,
    #[error("skill context budget exceeded")]
    ContextBudgetExceeded,
    #[error("skill context internal error")]
    Internal,
}

impl HostSkillContextBuildError {
    pub fn into_host_error(self) -> AgentLoopHostError {
        let kind = match self {
            Self::SourceUnavailable => AgentLoopHostErrorKind::Unavailable,
            Self::ParseFailed => AgentLoopHostErrorKind::InvalidInvocation,
            Self::TrustDataMissing | Self::VisibilityDataMissing => {
                AgentLoopHostErrorKind::PolicyDenied
            }
            Self::ContextBudgetExceeded => AgentLoopHostErrorKind::BudgetExceeded,
            Self::Internal => AgentLoopHostErrorKind::Internal,
        };
        AgentLoopHostError::new(kind, self.to_string())
    }
}

pub async fn build_skill_instruction_snippets(
    source: &(dyn HostSkillContextSource + Send + Sync),
    run_context: &LoopRunContext,
) -> Result<Vec<LoopContextSnippet>, AgentLoopHostError> {
    let candidates = source
        .load_skill_context_candidates(run_context)
        .await
        .map_err(HostSkillContextBuildError::into_host_error)?;
    let snapshot = build_skill_run_snapshot(candidates)
        .map_err(HostSkillContextBuildError::into_host_error)?;
    let service = SkillContextService::new(snapshot.clone());
    let snippets = service
        .skill_snippets(&snapshot)
        .await
        .map_err(skill_context_error_to_host_error)?;
    Ok(snippets
        .into_iter()
        .map(|snippet| snippet.into_loop_snippet())
        .collect())
}

pub fn build_skill_run_snapshot(
    candidates: Vec<HostSkillContextCandidate>,
) -> Result<SkillRunSnapshot, HostSkillContextBuildError> {
    if candidates.is_empty() {
        return Ok(SkillRunSnapshot::empty());
    }

    let mut entries = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let trust = candidate
            .trust
            .ok_or(HostSkillContextBuildError::TrustDataMissing)?;
        let visibility = candidate
            .visibility
            .ok_or(HostSkillContextBuildError::VisibilityDataMissing)?;
        if visibility != SkillVisibility::Visible {
            continue;
        }
        let skill_md = candidate
            .skill_md
            .ok_or(HostSkillContextBuildError::SourceUnavailable)?;
        let parsed =
            parse_skill_md(&skill_md).map_err(|_| HostSkillContextBuildError::ParseFailed)?;
        entries.push(parsed_skill_to_snapshot_entry(
            parsed,
            trust,
            visibility,
            candidate.ordering_key,
        ));
    }

    Ok(SkillRunSnapshot::from_entries(entries))
}

fn parsed_skill_to_snapshot_entry(
    parsed: ParsedSkill,
    trust: SkillTrust,
    visibility: SkillVisibility,
    ordering_key: Option<String>,
) -> InstalledSkillSnapshot {
    let name = parsed.manifest.name;
    InstalledSkillSnapshot {
        ordering_key: ordering_key.unwrap_or_else(|| name.clone()),
        name,
        trust: skill_trust_level(trust),
        visibility,
        prompt_content: Some(parsed.prompt_content),
        safe_description: parsed.manifest.description,
    }
}

fn skill_trust_level(trust: SkillTrust) -> SkillTrustLevel {
    match trust {
        SkillTrust::Installed => SkillTrustLevel::Installed,
        SkillTrust::Trusted => SkillTrustLevel::Trusted,
    }
}

fn skill_context_error_to_host_error(error: SkillContextError) -> AgentLoopHostError {
    let build_error = match error {
        SkillContextError::TrustDataMissing => HostSkillContextBuildError::TrustDataMissing,
        SkillContextError::VisibilityDataMissing => {
            HostSkillContextBuildError::VisibilityDataMissing
        }
        SkillContextError::ContextBudgetExceeded => {
            HostSkillContextBuildError::ContextBudgetExceeded
        }
        SkillContextError::InvalidSnapshotVersion | SkillContextError::Internal => {
            HostSkillContextBuildError::Internal
        }
    };
    build_error.into_host_error()
}

pub(crate) fn snippet_model_message_ref(
    snippet_ref: &str,
    safe_summary: &str,
    ordinal: usize,
) -> Result<LoopMessageRef, AgentLoopHostError> {
    let slug = sanitize_ref_suffix(snippet_ref);
    let hash = stable_snippet_ref_hash(snippet_ref, safe_summary, ordinal);
    LoopMessageRef::new(format!("msg:snippet.{slug}.{ordinal}.{hash:016x}")).map_err(|_| {
        AgentLoopHostError::new(
            AgentLoopHostErrorKind::Internal,
            "skill context snippet reference could not be represented",
        )
    })
}

pub(crate) fn is_snippet_model_message_ref(content_ref: &LoopMessageRef) -> bool {
    content_ref.as_str().starts_with("msg:snippet.")
}

fn sanitize_ref_suffix(value: &str) -> String {
    let mut suffix = String::with_capacity(value.len().min(96));
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            suffix.push(character);
        } else {
            suffix.push('.');
        }
        if suffix.len() >= 96 {
            break;
        }
    }
    let suffix = suffix.trim_matches('.');
    if suffix.is_empty() {
        "context".to_string()
    } else {
        suffix.to_string()
    }
}

fn stable_snippet_ref_hash(snippet_ref: &str, safe_summary: &str, ordinal: usize) -> u64 {
    let mut hash = FNV_OFFSET;
    feed_hash(&mut hash, snippet_ref.as_bytes());
    feed_hash(&mut hash, &[0xFF]);
    feed_hash(&mut hash, safe_summary.as_bytes());
    feed_hash(&mut hash, &[0xFF]);
    feed_hash(&mut hash, ordinal.to_string().as_bytes());
    hash
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001B3;

fn feed_hash(hash: &mut u64, bytes: &[u8]) {
    for &byte in bytes {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}
