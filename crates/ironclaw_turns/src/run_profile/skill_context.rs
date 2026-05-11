//! Skill context selection for the agent loop-support boundary.
//!
//! This module provides [`SkillContextService`] and the [`SkillContextSource`] trait,
//! which select model-visible skill context from a host-approved run snapshot.
//!
//! # Trust and Visibility Model
//!
//! Every installed skill in a run has two dimensions that gate what the model sees:
//!
//! - **Trust level** ([`SkillTrustLevel`]): determines how much content the model receives.
//!   `Trusted` skills include their full prompt content; `Installed` skills expose only
//!   a safe description.
//!
//! - **Visibility** ([`SkillVisibility`]): determines whether the model sees the skill at all.
//!   `Visible` skills appear in the context; `Hidden` and `Denied` skills are omitted entirely
//!   so the model has no knowledge of their existence.
//!
//! # Fail-closed semantics
//!
//! If trust or visibility data is missing (e.g., the snapshot version is empty), the service
//! returns an error rather than silently degrading. This ensures that an unconfigured or
//! corrupt snapshot never leaks capabilities to the model.
//!
//! # Determinism
//!
//! Output ordering is deterministic for the same [`SkillRunSnapshot`]: entries are sorted
//! lexicographically by [`InstalledSkillSnapshot::ordering_key`], and the snapshot version
//! is a deterministic hash of all entry data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::LoopContextSnippet;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error returned by [`SkillContextSource`] when skill context cannot be produced.
///
/// All variants are sanitized — no raw internals, file paths, or secret handles are leaked.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SkillContextError {
    /// Trust data is missing or the snapshot is in an inconsistent state.
    #[error("skill context: trust data missing")]
    TrustDataMissing,

    /// Visibility data is missing for one or more skills.
    #[error("skill context: visibility data missing")]
    VisibilityDataMissing,

    /// An internal error that cannot be attributed to trust or visibility.
    #[error("skill context: internal error")]
    Internal,
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Host-approved visibility status for a skill in a run.
///
/// Controls whether the model is aware of the skill's existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillVisibility {
    /// The skill is visible to the model and included in context.
    Visible,
    /// The skill exists but is hidden from the model — no mention in output.
    Hidden,
    /// The skill is explicitly denied — no mention in output.
    Denied,
}

/// Trust level for an installed skill, owned by this crate.
///
/// Mirrors the upstream `SkillTrust` enum without creating a production dependency
/// on `ironclaw_skills`.
///
/// - `Installed`: read-only context; the model sees only the safe description.
/// - `Trusted`: full context; the model sees description and prompt content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillTrustLevel {
    /// Registry/external skill — description only, no prompt content.
    Installed,
    /// User-placed/trusted skill — description and prompt content.
    Trusted,
}

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

/// Immutable, host-approved state of a single installed skill for a run.
///
/// Captures everything the service needs to decide what the model sees.
/// Must not contain raw file paths, capability IDs, secret handles, or
/// other internal metadata — only model-safe data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstalledSkillSnapshot {
    /// Human-readable name of the skill.
    pub name: String,
    /// Trust level — determines how much content the model receives.
    pub trust: SkillTrustLevel,
    /// Visibility — determines whether the model sees this skill at all.
    pub visibility: SkillVisibility,
    /// Full prompt content. Only included in model context when
    /// `trust == Trusted` and `visibility == Visible`.
    pub prompt_content: Option<String>,
    /// Sanitized description safe for model consumption.
    pub safe_description: String,
    /// Key used for deterministic lexicographic sorting of output.
    pub ordering_key: String,
}

/// Complete set of installed skill snapshots for a run.
///
/// The `snapshot_version` is a deterministic hash of all entries, used to verify
/// that two snapshots built from the same data produce identical context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRunSnapshot {
    /// All installed skill entries for this run.
    pub entries: Vec<InstalledSkillSnapshot>,
    /// Deterministic version string derived from entry data.
    /// An empty version indicates missing/corrupt trust data and triggers fail-closed behavior.
    pub snapshot_version: String,
}

impl SkillRunSnapshot {
    /// Create an empty snapshot for the no-skills case.
    ///
    /// Returns a stable, valid snapshot with an empty entry list and a fixed version string.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            snapshot_version: "empty".to_string(),
        }
    }

    /// Build a snapshot from a list of entries with a deterministic version hash.
    ///
    /// Entries are sorted by `ordering_key` before hashing so that insertion order
    /// does not affect the version.
    pub fn from_entries(mut entries: Vec<InstalledSkillSnapshot>) -> Self {
        entries.sort_by(|a, b| a.ordering_key.cmp(&b.ordering_key));
        let version = compute_snapshot_version(&entries);
        Self {
            entries,
            snapshot_version: version,
        }
    }
}

/// Snippet data produced by [`SkillContextSource`], ready for conversion into
/// a [`LoopContextSnippet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillContextSnippet {
    /// Reference identifier, e.g. `skill:<name>`.
    pub snippet_ref: String,
    /// Sanitized summary containing only the safe description and optionally prompt content.
    pub safe_summary: String,
}

impl SkillContextSnippet {
    /// Convert into the loop-layer [`LoopContextSnippet`] type.
    pub fn into_loop_snippet(self) -> LoopContextSnippet {
        LoopContextSnippet {
            snippet_ref: self.snippet_ref,
            safe_summary: self.safe_summary,
        }
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Port for selecting model-visible skill context from a host-approved run snapshot.
///
/// Implementations must be deterministic for the same inputs, trust-aware, and fail-closed
/// when trust or visibility data is missing. They must never grant authority or make
/// hidden/denied capabilities invokable.
#[async_trait]
pub trait SkillContextSource: Send + Sync {
    /// Produce skill context snippets from the service's held state.
    async fn skill_snippets(&self) -> Result<Vec<SkillContextSnippet>, SkillContextError>;
}

// ---------------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------------

/// Deterministic, trust-aware skill context service.
///
/// Holds a [`SkillRunSnapshot`] and produces model-visible context snippets
/// following the trust/visibility rules documented at the module level.
pub struct SkillContextService {
    snapshot: SkillRunSnapshot,
}

impl SkillContextService {
    /// Create a new service from a host-approved run snapshot.
    pub fn new(snapshot: SkillRunSnapshot) -> Self {
        Self { snapshot }
    }
}

#[async_trait]
impl SkillContextSource for SkillContextService {
    async fn skill_snippets(&self) -> Result<Vec<SkillContextSnippet>, SkillContextError> {
        // Fail closed on missing/corrupt trust data.
        if self.snapshot.snapshot_version.is_empty() {
            return Err(SkillContextError::TrustDataMissing);
        }

        let mut visible: Vec<&InstalledSkillSnapshot> = self
            .snapshot
            .entries
            .iter()
            .filter(|entry| entry.visibility == SkillVisibility::Visible)
            .collect();

        // Deterministic ordering by ordering_key.
        // Re-sort here even though `from_entries` sorts, because the snapshot
        // may have been constructed manually with unsorted entries.
        visible.sort_by(|a, b| a.ordering_key.cmp(&b.ordering_key));

        let snippets = visible
            .into_iter()
            .map(|entry| {
                let safe_summary = match entry.trust {
                    SkillTrustLevel::Trusted => {
                        if let Some(ref content) = entry.prompt_content {
                            format!("{}\n\n{}", entry.safe_description, content)
                        } else {
                            entry.safe_description.clone()
                        }
                    }
                    SkillTrustLevel::Installed => entry.safe_description.clone(),
                };
                SkillContextSnippet {
                    snippet_ref: format!("skill:{}", entry.name),
                    safe_summary,
                }
            })
            .collect();

        Ok(snippets)
    }
}

// ---------------------------------------------------------------------------
// Noop implementation
// ---------------------------------------------------------------------------

/// A no-op implementation of [`SkillContextSource`] that always returns an empty list.
///
/// Useful for composition and testing when no skill context is needed.
pub struct NoopSkillContextSource;

#[async_trait]
impl SkillContextSource for NoopSkillContextSource {
    async fn skill_snippets(&self) -> Result<Vec<SkillContextSnippet>, SkillContextError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic version string from sorted snapshot entries.
///
/// Uses a simple FNV-1a-style hash over the concatenated field data.
/// This hash is stable across runs of the same binary. It is not cryptographic
/// and should not be used for security purposes.
fn compute_snapshot_version(sorted_entries: &[InstalledSkillSnapshot]) -> String {
    // FNV-1a 64-bit — stable, simple, no external dependency.
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET;

    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };

    for entry in sorted_entries {
        feed(entry.name.as_bytes());
        feed(&[0xFF]); // separator
        feed(match entry.trust {
            SkillTrustLevel::Installed => b"installed",
            SkillTrustLevel::Trusted => b"trusted",
        });
        feed(&[0xFF]);
        feed(match entry.visibility {
            SkillVisibility::Visible => b"visible",
            SkillVisibility::Hidden => b"hidden",
            SkillVisibility::Denied => b"denied",
        });
        feed(&[0xFF]);
        if let Some(ref content) = entry.prompt_content {
            feed(content.as_bytes());
        }
        feed(&[0xFF]);
        feed(entry.safe_description.as_bytes());
        feed(&[0xFF]);
        feed(entry.ordering_key.as_bytes());
        feed(&[0xFE]); // entry separator
    }

    format!("v1:{hash:016x}")
}
