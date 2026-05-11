//! Production [`MemoryPromptContextService`] adapter backed by [`MemoryBackend`].
//!
//! This adapter bridges the Reborn memory search subsystem into the agent loop
//! context pipeline. It derives a [`MemoryDocumentScope`] from the request's
//! [`TurnScope`] and [`TurnActor`], builds a [`MemorySearchRequest`], delegates
//! to [`MemoryBackend::search`], and maps the results to sanitized
//! [`LoopContextSnippet`] values suitable for model consumption.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_memory::{
    MemoryBackend, MemoryContext, MemoryDocumentPath, MemoryDocumentScope, MemorySearchRequest,
    MemorySearchResult,
};
use ironclaw_turns::run_profile::{
    AgentLoopHostError, AgentLoopHostErrorKind, ContextProfileId, LoopContextSnippet,
    LoopSafeSummary, MemoryPromptContextRequest, MemoryPromptContextService,
};

/// Maximum byte length for a snippet safe summary, matching `LoopSafeSummary`
/// validation (512 bytes).
const MAX_SAFE_SUMMARY_BYTES: usize = 512;

/// Production adapter that loads memory snippets via [`MemoryBackend::search`].
///
/// # Isolation guarantees
///
/// The adapter derives [`MemoryDocumentScope`] from the request's [`TurnScope`]
/// and [`TurnActor`] on every call. The scope is passed to the backend as a
/// [`MemoryContext`], ensuring that cross-tenant and cross-user data never leaks
/// into a run's context.
///
/// # Determinism contract
///
/// Results are sorted by score descending, then by path ascending, before
/// truncation. This guarantees deterministic ordering for the same backend
/// results regardless of the backend's internal ordering.
///
/// # Error handling
///
/// Backend errors are mapped to [`AgentLoopHostError`] with
/// [`AgentLoopHostErrorKind::Unavailable`]. Raw backend error messages are
/// never exposed in the safe summary.
pub struct ProductionMemoryPromptContextService {
    backend: Arc<dyn MemoryBackend>,
}

impl ProductionMemoryPromptContextService {
    /// Create a new production adapter wrapping the given memory backend.
    pub fn new(backend: Arc<dyn MemoryBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl MemoryPromptContextService for ProductionMemoryPromptContextService {
    async fn load_memory_snippets(
        &self,
        request: MemoryPromptContextRequest,
    ) -> Result<Vec<LoopContextSnippet>, AgentLoopHostError> {
        if request.max_snippets == 0 {
            return Ok(Vec::new());
        }

        let Some(scope) = build_memory_scope(&request)? else {
            return Ok(Vec::new());
        };
        let context = MemoryContext::new(scope);

        let search_request = MemorySearchRequest::new(&request.query).map_err(|_| {
            AgentLoopHostError::new(
                AgentLoopHostErrorKind::InvalidInvocation,
                "memory search query is invalid",
            )
        })?;
        let search_request = search_request.with_limit(request.max_snippets);

        let mut results = self
            .backend
            .search(&context, search_request)
            .await
            .map_err(|_| {
                AgentLoopHostError::new(
                    AgentLoopHostErrorKind::Unavailable,
                    "memory context unavailable",
                )
            })?;

        results.retain(|result| result.path.scope() == context.scope());

        // Enforce deterministic ordering: score descending, path ascending.
        // Production backends (libsql/postgres) already sort this way via
        // `fuse_memory_search_results`, but the `MemoryBackend::search` trait
        // contract does not guarantee ordering, so we sort defensively.
        results.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.path.relative_path().cmp(right.path.relative_path()))
        });

        results.truncate(request.max_snippets);

        let snippets = results
            .into_iter()
            .filter_map(map_search_result_to_snippet)
            .collect();

        Ok(snippets)
    }
}

/// Build a [`MemoryDocumentScope`] from the request's scope and actor fields.
fn build_memory_scope(
    request: &MemoryPromptContextRequest,
) -> Result<Option<MemoryDocumentScope>, AgentLoopHostError> {
    match memory_context_policy(&request.context_profile_id) {
        MemoryContextPolicy::Disabled => Ok(None),
        MemoryContextPolicy::PrimaryScope => MemoryDocumentScope::new_with_agent(
            request.scope.tenant_id.as_str(),
            request.actor.user_id.as_str(),
            request.scope.agent_id.as_ref().map(|id| id.as_str()),
            request.scope.project_id.as_ref().map(|id| id.as_str()),
        )
        .map(Some)
        .map_err(|_| {
            AgentLoopHostError::new(
                AgentLoopHostErrorKind::Internal,
                "memory context scope construction failed",
            )
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryContextPolicy {
    Disabled,
    PrimaryScope,
}

/// Resolve the narrow context-memory policy available in this slice.
///
/// The run-profile layer already resolves the profile identifier. Until a full
/// context-policy registry exists here, the adapter supports an explicit
/// memory-disabled profile and otherwise uses the request's primary
/// tenant/user/agent/project scope.
fn memory_context_policy(context_profile_id: &ContextProfileId) -> MemoryContextPolicy {
    match context_profile_id.as_str() {
        "memory_disabled" | "memory-disabled" | "disabled_context" | "context_disabled" => {
            MemoryContextPolicy::Disabled
        }
        _ => MemoryContextPolicy::PrimaryScope,
    }
}

/// Map a [`MemorySearchResult`] to a [`LoopContextSnippet`], sanitizing the
/// safe summary through [`LoopSafeSummary`] validation.
///
/// Returns `None` if the snippet cannot be sanitized into a valid safe summary
/// (e.g. it contains only forbidden characters). This is a graceful degradation
/// — the snippet is silently dropped rather than failing the entire load.
fn map_search_result_to_snippet(result: MemorySearchResult) -> Option<LoopContextSnippet> {
    let snippet_ref = snippet_ref_for_path(&result.path);
    let safe_summary = sanitize_snippet_text(&result.snippet)?;
    Some(LoopContextSnippet {
        snippet_ref,
        safe_summary,
    })
}

fn snippet_ref_for_path(path: &MemoryDocumentPath) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    update_hash(&mut hash, path.tenant_id());
    update_hash(&mut hash, path.user_id());
    update_hash(&mut hash, path.agent_id().unwrap_or(""));
    update_hash(&mut hash, path.project_id().unwrap_or(""));
    update_hash(&mut hash, path.relative_path());
    format!("memory-snippet:{hash:016x}")
}

fn update_hash(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x100000001b3);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(0x100000001b3);
}

/// Sanitize a raw snippet string into a model-safe summary.
///
/// - Strips control characters (NUL, tabs, etc.)
/// - Truncates to `MAX_SAFE_SUMMARY_BYTES`
/// - Validates through [`LoopSafeSummary::new`] which rejects path delimiters,
///   sensitive markers, and API-key-like tokens
///
/// Returns `None` if the sanitized text fails `LoopSafeSummary` validation.
fn sanitize_snippet_text(raw: &str) -> Option<String> {
    // Strip control characters first.
    let cleaned: String = raw.chars().filter(|ch| !ch.is_control()).collect();

    if cleaned.is_empty() {
        return None;
    }

    // Truncate to the byte limit, respecting char boundaries.
    let truncated = if cleaned.len() > MAX_SAFE_SUMMARY_BYTES {
        let mut end = MAX_SAFE_SUMMARY_BYTES;
        while end > 0 && !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        &cleaned[..end]
    } else {
        &cleaned
    };

    if truncated.is_empty() {
        return None;
    }

    // Validate through LoopSafeSummary which rejects path delimiters,
    // sensitive markers, and API-key-like tokens.
    match LoopSafeSummary::new(truncated) {
        Ok(summary) => Some(summary.as_str().to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_characters() {
        let raw = "hello\x00world\ttab\nnewline";
        let result = sanitize_snippet_text(raw);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(!text.chars().any(|c| c.is_control()));
        assert!(text.contains("helloworld"));
    }

    #[test]
    fn sanitize_truncates_long_text() {
        let raw = "a".repeat(1000);
        let result = sanitize_snippet_text(&raw);
        assert!(result.is_some());
        assert!(result.unwrap().len() <= MAX_SAFE_SUMMARY_BYTES);
    }

    #[test]
    fn sanitize_rejects_empty_after_stripping() {
        let raw = "\x00\x01\x02";
        assert!(sanitize_snippet_text(raw).is_none());
    }

    #[test]
    fn sanitize_rejects_path_delimiters() {
        // LoopSafeSummary rejects raw path delimiters like `/` and `\`
        let raw = "/etc/passwd";
        assert!(sanitize_snippet_text(raw).is_none());
    }

    #[test]
    fn sanitize_rejects_sensitive_markers() {
        let raw = "the api key is exposed";
        assert!(sanitize_snippet_text(raw).is_none());
    }

    #[test]
    fn sanitize_accepts_clean_text() {
        let raw = "Memory note about project planning";
        let result = sanitize_snippet_text(raw);
        assert_eq!(result.as_deref(), Some(raw));
    }
}
