use std::time::SystemTime;

use ironclaw_host_api::{HostApiError, ScopedPath, VirtualPath};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::index::IndexName;
use crate::record::RecordVersion;

/// Filesystem operation used for permission checks and audit/error reporting.
///
/// The legacy byte-plane variants (`ReadFile`, `WriteFile`, …) describe the
/// *intent* of an operation against the underlying [`MountPermissions`]
/// surface and are reused by the unified `put`/`get` ops as their permission
/// witness — `put` is a write, `get` is a read. The newer variants
/// (`Query`, `EnsureIndex`, `BeginTxn`, `Tail`) describe operations that have
/// no analogue in the legacy enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemOperation {
    MountLocal,
    ReadFile,
    WriteFile,
    AppendFile,
    ListDir,
    Stat,
    Delete,
    CreateDirAll,
    Query,
    EnsureIndex,
    BeginTxn,
    Tail,
}

impl std::fmt::Display for FilesystemOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MountLocal => "mount_local",
            Self::ReadFile => "read_file",
            Self::WriteFile => "write_file",
            Self::AppendFile => "append_file",
            Self::ListDir => "list_dir",
            Self::Stat => "stat",
            Self::Delete => "delete",
            Self::CreateDirAll => "create_dir_all",
            Self::Query => "query",
            Self::EnsureIndex => "ensure_index",
            Self::BeginTxn => "begin_txn",
            Self::Tail => "tail",
        })
    }
}

/// Filesystem service failures.
///
/// Display output intentionally uses scoped/virtual paths rather than raw host
/// paths. Backend implementations may log lower-level errors separately, but
/// user-facing errors should preserve host path confidentiality.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FilesystemError {
    #[error(transparent)]
    Contract(#[from] HostApiError),
    #[error("permission denied for {operation} on scoped path {path}")]
    PermissionDenied {
        path: ScopedPath,
        operation: FilesystemOperation,
    },
    #[error("no backend mount found for virtual path {path}")]
    MountNotFound { path: VirtualPath },
    #[error("virtual path not found for {operation} at {path}")]
    NotFound {
        path: VirtualPath,
        operation: FilesystemOperation,
    },
    #[error("virtual path escaped backend mount {path}")]
    PathOutsideMount { path: VirtualPath },
    #[error("symlink escapes backend mount at virtual path {path}")]
    SymlinkEscape { path: VirtualPath },
    #[error("backend mount conflict at virtual path {path}")]
    MountConflict { path: VirtualPath },
    #[error("filesystem backend error during {operation} at {path}: {reason}")]
    Backend {
        path: VirtualPath,
        operation: FilesystemOperation,
        reason: String,
    },
    /// Compare-and-swap precondition failed: the existing record's version did
    /// not match the caller's expectation. Stores typically retry by reading
    /// the current version and re-applying the transformation.
    #[error("version mismatch at {path}: expected {expected:?}, found {found:?}")]
    VersionMismatch {
        path: VirtualPath,
        expected: Option<RecordVersion>,
        found: Option<RecordVersion>,
    },
    /// Mounted backend does not implement the requested operation. Capability
    /// checks at mount time should catch most cases; this remains for
    /// runtime-conditional capabilities (e.g. a Postgres mount built against a
    /// server without `pgvector` rejecting `IndexKind::Vector`).
    #[error("operation {operation} is not supported by the mount at {path}")]
    Unsupported {
        path: VirtualPath,
        operation: FilesystemOperation,
    },
    /// Declaring an index conflicted with an existing definition (e.g. the
    /// same name already exists with a different `keys` ordering or `kind`).
    #[error("index conflict for {name} at {path}: {reason}")]
    IndexConflict {
        path: VirtualPath,
        name: IndexName,
        reason: String,
    },
}

/// Coarse file type returned by [`FileStat`] and [`DirEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Other,
}

/// Directory entry returned by [`RootFilesystem::list_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub path: VirtualPath,
    pub file_type: FileType,
}

/// File metadata returned by [`RootFilesystem::stat`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    pub path: VirtualPath,
    pub file_type: FileType,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub sensitive: bool,
}

/// Stable identifier for a mounted filesystem backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendId(String);

impl BackendId {
    pub fn new(value: impl Into<String>) -> Result<Self, HostApiError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(HostApiError::InvalidId {
                kind: "filesystem backend",
                value,
                reason: "backend id must not be empty".to_string(),
            });
        }
        if value.contains('/')
            || value.contains('\\')
            || value.contains('\0')
            || value.chars().any(char::is_control)
        {
            return Err(HostApiError::InvalidId {
                kind: "filesystem backend",
                value,
                reason: "backend id must be a simple non-path identifier".to_string(),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Coarse class of backend implementation behind a virtual mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendKind {
    LocalFilesystem,
    DatabaseFilesystem,
    MemoryDocuments,
    ObjectStore,
    Custom(String),
}

/// Storage shape represented by a mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// File-like contents addressed by virtual paths.
    FileContent,
    /// Structured records that may expose file-shaped projections.
    StructuredRecords,
    /// Derived data such as chunks, indexes, or embeddings.
    DerivedProjection,
}

/// Semantic kind of content exposed at a mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    GenericFile,
    ProjectFile,
    Artifact,
    MemoryDocument,
    SystemState,
    ExtensionPackage,
    StructuredRecord,
}

/// Indexing/embedding policy associated with file-shaped content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexPolicy {
    NotIndexed,
    FullText,
    Vector,
    FullTextAndVector,
    BackendDefined,
}

/// Index kinds a backend can materialize when it serves the record plane.
///
/// A backend that cannot serve a requested kind fails [`ensure_index`](
/// crate::StorageBackend::ensure_index) closed with
/// [`FilesystemError::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IndexCapability {
    pub exact: bool,
    pub prefix: bool,
    pub fts: bool,
    pub vector: bool,
}

impl IndexCapability {
    /// Convenience constructor for backends that serve everything the byte
    /// plane needs (most SQL backends).
    pub const fn sql_typical() -> Self {
        Self {
            exact: true,
            prefix: true,
            fts: false,
            vector: false,
        }
    }
}

/// Transaction semantics offered by a backend.
///
/// Stores must work with `Cas` as the floor; richer backends opt into
/// `MultiKey` for stronger guarantees, but consumers never *depend* on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnCapability {
    #[default]
    None,
    /// Compare-and-swap on individual records (see
    /// [`CasExpectation`](crate::CasExpectation)).
    Cas,
    /// Backend implements [`StorageTxn`](crate::StorageTxn) for atomic
    /// multi-key updates within a single mount.
    MultiKey,
}

/// Capabilities advertised by a mounted backend for diagnostics and routing.
///
/// Mount-time validation refuses a backend whose capabilities cannot satisfy
/// the index/record/transaction needs declared by the consumer that will be
/// constructed against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BackendCapabilities {
    // Bytes plane.
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub list: bool,
    pub stat: bool,
    pub delete: bool,
    // Record plane.
    pub records: bool,
    pub query: bool,
    pub index: IndexCapability,
    pub txn: TxnCapability,
    // Event plane (append/tail).
    pub events: bool,
    // Legacy flags retained for existing catalog consumers.
    pub indexed: bool,
    pub embedded: bool,
}
