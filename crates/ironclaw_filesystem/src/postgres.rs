use std::collections::BTreeMap;

use async_trait::async_trait;
use ironclaw_host_api::VirtualPath;

use crate::db::{
    child_path_like_pattern, db_error, direct_children, directory_append_error,
    directory_write_error, is_not_found, not_found, system_time_from_unix_seconds,
    valid_engine_path, virtual_path_prefixes,
};
use crate::{
    BackendCapabilities, CasExpectation, ContentType, DirEntry, Entry, FileStat, FileType,
    FilesystemError, FilesystemOperation, IndexCapability, IndexKey, IndexValue, RecordKind,
    RecordVersion, RootFilesystem, TxnCapability, VersionedEntry,
};

#[cfg(feature = "postgres")]
/// PostgreSQL-backed [`RootFilesystem`] storing file contents by virtual path.
pub struct PostgresRootFilesystem {
    pool: deadpool_postgres::Pool,
}

#[cfg(feature = "postgres")]
impl PostgresRootFilesystem {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    pub async fn run_migrations(&self) -> Result<(), FilesystemError> {
        let client = self.client().await?;
        client
            .batch_execute(POSTGRES_ROOT_FILESYSTEM_SCHEMA)
            .await
            .map_err(|error| {
                db_error(
                    valid_engine_path(),
                    FilesystemOperation::CreateDirAll,
                    error,
                )
            })
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, FilesystemError> {
        self.pool
            .get()
            .await
            .map_err(|error| FilesystemError::Backend {
                path: valid_engine_path(),
                operation: FilesystemOperation::Stat,
                reason: error.to_string(),
            })
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl RootFilesystem for PostgresRootFilesystem {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            read: true,
            write: true,
            append: true,
            list: true,
            stat: true,
            delete: true,
            records: true,
            query: false,
            index: IndexCapability {
                exact: false,
                prefix: false,
                fts: false,
                vector: false,
            },
            txn: TxnCapability::Cas,
            events: false,
            indexed: false,
            embedded: false,
        }
    }

    async fn put(
        &self,
        path: &VirtualPath,
        entry: Entry,
        cas: CasExpectation,
    ) -> Result<RecordVersion, FilesystemError> {
        let client = self.client().await?;
        if matches!(
            self.exact_entry_with_client(&client, path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry_with_client(&client, path).await?
        {
            return Err(directory_write_error(path.clone()));
        }
        let indexed_json =
            serde_json::to_value(&entry.indexed).map_err(|error| FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::WriteFile,
                reason: format!("failed to serialize indexed projection: {error}"),
            })?;
        let kind_str = entry.kind.as_ref().map(|k| k.as_str().to_string());
        let content_type_str = entry.content_type.as_str().to_string();
        let body = entry.body;
        let path_str = path.as_str();

        match cas {
            CasExpectation::Absent => {
                let rows = client
                    .execute(
                        r#"
                        INSERT INTO root_filesystem_entries
                            (path, contents, is_dir, content_type, kind, indexed, version)
                        VALUES ($1, $2, FALSE, $3, $4, $5, 1)
                        ON CONFLICT (path) DO NOTHING
                        "#,
                        &[
                            &path_str,
                            &body,
                            &content_type_str,
                            &kind_str,
                            &indexed_json,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                if rows == 0 {
                    let found = self.current_version_with_client(&client, path).await?;
                    return Err(FilesystemError::VersionMismatch {
                        path: path.clone(),
                        expected: None,
                        found,
                    });
                }
                Ok(RecordVersion::from_backend(1))
            }
            CasExpectation::Version(expected) => {
                let expected_raw = expected.get() as i64;
                let rows = client
                    .execute(
                        r#"
                        UPDATE root_filesystem_entries
                        SET contents = $1,
                            content_type = $2,
                            kind = $3,
                            indexed = $4,
                            version = version + 1,
                            updated_at = NOW()
                        WHERE path = $5 AND is_dir = FALSE AND version = $6
                        "#,
                        &[
                            &body,
                            &content_type_str,
                            &kind_str,
                            &indexed_json,
                            &path_str,
                            &expected_raw,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                if rows == 0 {
                    let found = self.current_version_with_client(&client, path).await?;
                    return Err(FilesystemError::VersionMismatch {
                        path: path.clone(),
                        expected: Some(expected),
                        found,
                    });
                }
                Ok(expected.next())
            }
            CasExpectation::Any => {
                let row = client
                    .query_opt(
                        r#"
                        INSERT INTO root_filesystem_entries
                            (path, contents, is_dir, content_type, kind, indexed, version)
                        VALUES ($1, $2, FALSE, $3, $4, $5, 1)
                        ON CONFLICT (path) DO UPDATE SET
                            contents = EXCLUDED.contents,
                            content_type = EXCLUDED.content_type,
                            kind = EXCLUDED.kind,
                            indexed = EXCLUDED.indexed,
                            version = root_filesystem_entries.version + 1,
                            updated_at = NOW()
                        WHERE root_filesystem_entries.is_dir = FALSE
                        RETURNING version
                        "#,
                        &[
                            &path_str,
                            &body,
                            &content_type_str,
                            &kind_str,
                            &indexed_json,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                let Some(row) = row else {
                    return Err(directory_write_error(path.clone()));
                };
                let version: i64 = row.get("version");
                Ok(RecordVersion::from_backend(version.max(0) as u64))
            }
        }
    }

    async fn get(&self, path: &VirtualPath) -> Result<Option<VersionedEntry>, FilesystemError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                r#"
                SELECT contents, is_dir, content_type, kind, indexed, version
                FROM root_filesystem_entries
                WHERE path = $1
                "#,
                &[&path.as_str()],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let is_dir: bool = row.get("is_dir");
        if is_dir {
            return Ok(None);
        }
        let body: Vec<u8> = row.get("contents");
        let content_type_raw: String = row.get("content_type");
        let kind_raw: Option<String> = row.get("kind");
        let indexed_value: serde_json::Value = row.get("indexed");
        let version_raw: i64 = row.get("version");
        let entry = build_entry(path, body, content_type_raw, kind_raw, indexed_value)?;
        Ok(Some(VersionedEntry {
            entry,
            version: RecordVersion::from_backend(version_raw.max(0) as u64),
        }))
    }

    async fn read_file(&self, path: &VirtualPath) -> Result<Vec<u8>, FilesystemError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT contents, is_dir FROM root_filesystem_entries WHERE path = $1",
                &[&path.as_str()],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let Some(row) = row else {
            return Err(not_found(path.clone(), FilesystemOperation::ReadFile));
        };
        let is_dir: bool = row.get("is_dir");
        if is_dir {
            return Err(FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::ReadFile,
                reason: "is a directory".to_string(),
            });
        }
        Ok(row.get("contents"))
    }

    async fn write_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        let client = self.client().await?;
        if matches!(
            self.exact_entry_with_client(&client, path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry_with_client(&client, path).await?
        {
            return Err(directory_write_error(path.clone()));
        }
        // PR #3660 reviewer fix: legacy write_file must reset content_type
        // / kind / indexed and bump version, otherwise get() after
        // write_file-overwrite of a previously record-shaped entry
        // returns stale metadata.
        let rows = client
            .execute(
                r#"
                INSERT INTO root_filesystem_entries
                    (path, contents, is_dir, content_type, kind, indexed, version)
                VALUES ($1, $2, FALSE, 'application/octet-stream', NULL, '{}'::jsonb, 1)
                ON CONFLICT (path) DO UPDATE SET
                    contents = EXCLUDED.contents,
                    is_dir = FALSE,
                    content_type = EXCLUDED.content_type,
                    kind = EXCLUDED.kind,
                    indexed = EXCLUDED.indexed,
                    version = root_filesystem_entries.version + 1,
                    updated_at = NOW()
                WHERE root_filesystem_entries.is_dir = FALSE
                "#,
                &[&path.as_str(), &bytes],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::WriteFile, error))?;
        if rows == 0 {
            return Err(directory_write_error(path.clone()));
        }
        Ok(())
    }

    async fn append_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        let client = self.client().await?;
        if matches!(
            self.exact_entry_with_client(&client, path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry_with_client(&client, path).await?
        {
            return Err(directory_append_error(path.clone()));
        }
        // PR #3660 reviewer fix: append also resets schema metadata.
        // Appending bytes onto a previously record-shaped entry was always
        // a category error; surface it by clearing the schema metadata
        // rather than leaving it stale on top of changed bytes.
        // TODO(reborn): append rewrites the whole DB row. Do not use this
        // path for high-volume JSONL/event streams; route those through
        // typed event stores or append-capable artifact backends.
        client
            .execute(
                r#"
                INSERT INTO root_filesystem_entries
                    (path, contents, is_dir, content_type, kind, indexed, version)
                VALUES ($1, $2, FALSE, 'application/octet-stream', NULL, '{}'::jsonb, 1)
                ON CONFLICT (path) DO UPDATE SET
                    contents = root_filesystem_entries.contents || EXCLUDED.contents,
                    is_dir = FALSE,
                    content_type = EXCLUDED.content_type,
                    kind = EXCLUDED.kind,
                    indexed = EXCLUDED.indexed,
                    version = root_filesystem_entries.version + 1,
                    updated_at = NOW()
                "#,
                &[&path.as_str(), &bytes],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::AppendFile, error))?;
        Ok(())
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        let client = self.client().await?;
        let exact_entry = self.exact_entry_with_client(&client, path).await?;
        if matches!(exact_entry, Some((_, FileType::File, _))) {
            return Err(FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::ListDir,
                reason: "not a directory".to_string(),
            });
        }
        let rows = self
            .child_entries_with_client(&client, path, FilesystemOperation::ListDir)
            .await?;
        let children = direct_children(path, rows);
        if matches!(exact_entry, Some((_, FileType::Directory, _))) && is_not_found(&children) {
            return Ok(Vec::new());
        }
        children
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        let client = self.client().await?;
        if let Some((len, file_type, modified)) =
            self.exact_entry_with_client(&client, path).await?
        {
            return Ok(FileStat {
                path: path.clone(),
                file_type,
                len,
                modified,
                sensitive: false,
            });
        }
        if self.has_child_entry_with_client(&client, path).await? {
            return Ok(FileStat {
                path: path.clone(),
                file_type: FileType::Directory,
                len: 0,
                modified: None,
                sensitive: false,
            });
        }
        Err(not_found(path.clone(), FilesystemOperation::Stat))
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let client = self.client().await?;
        let child_pattern = child_path_like_pattern(path);
        let deleted = client
            .execute(
                "DELETE FROM root_filesystem_entries WHERE path = $1 OR path LIKE $2 ESCAPE '!'",
                &[&path.as_str(), &child_pattern],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::Delete, error))?;
        if deleted == 0 {
            return Err(not_found(path.clone(), FilesystemOperation::Delete));
        }
        Ok(())
    }

    async fn create_dir_all(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let mut client = self.client().await?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::CreateDirAll, error))?;
        for prefix in virtual_path_prefixes(path)? {
            let row = transaction
                .query_opt(
                    "SELECT is_dir FROM root_filesystem_entries WHERE path = $1",
                    &[&prefix.as_str()],
                )
                .await
                .map_err(|error| {
                    db_error(prefix.clone(), FilesystemOperation::CreateDirAll, error)
                })?;
            if row.is_some_and(|row| !row.get::<_, bool>("is_dir")) {
                return Err(FilesystemError::Backend {
                    path: prefix,
                    operation: FilesystemOperation::CreateDirAll,
                    reason: "file exists where directory is required".to_string(),
                });
            }
            transaction
                .execute(
                    r#"
                    INSERT INTO root_filesystem_entries (path, contents, is_dir)
                    VALUES ($1, ''::bytea, TRUE)
                    ON CONFLICT (path) DO NOTHING
                    "#,
                    &[&prefix.as_str()],
                )
                .await
                .map_err(|error| {
                    db_error(path.clone(), FilesystemOperation::CreateDirAll, error)
                })?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::CreateDirAll, error))?;
        Ok(())
    }
}

#[cfg(feature = "postgres")]
impl PostgresRootFilesystem {
    async fn exact_entry_with_client(
        &self,
        client: &tokio_postgres::Client,
        path: &VirtualPath,
    ) -> Result<Option<(u64, FileType, Option<std::time::SystemTime>)>, FilesystemError> {
        let row = client
            .query_opt(
                "SELECT OCTET_LENGTH(contents)::bigint AS len, is_dir, EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at_epoch FROM root_filesystem_entries WHERE path = $1",
                &[&path.as_str()],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::Stat, error))?;
        Ok(row.map(|row| {
            let len: i64 = row.get("len");
            let is_dir: bool = row.get("is_dir");
            let updated_at_epoch: i64 = row.get("updated_at_epoch");
            (
                if is_dir { 0 } else { len.max(0) as u64 },
                if is_dir {
                    FileType::Directory
                } else {
                    FileType::File
                },
                system_time_from_unix_seconds(updated_at_epoch),
            )
        }))
    }

    async fn child_entries_with_client(
        &self,
        client: &tokio_postgres::Client,
        parent: &VirtualPath,
        operation: FilesystemOperation,
    ) -> Result<Vec<(VirtualPath, u64, FileType)>, FilesystemError> {
        let pattern = child_path_like_pattern(parent);
        let rows = client
            .query(
                "SELECT path, OCTET_LENGTH(contents)::bigint AS len, is_dir FROM root_filesystem_entries WHERE path LIKE $1 ESCAPE '!' ORDER BY path",
                &[&pattern],
            )
            .await
            .map_err(|error| db_error(parent.clone(), operation, error))?;
        rows.into_iter()
            .map(|row| {
                let path: String = row.get("path");
                let len: i64 = row.get("len");
                let is_dir: bool = row.get("is_dir");
                Ok((
                    VirtualPath::new(path)?,
                    if is_dir { 0 } else { len.max(0) as u64 },
                    if is_dir {
                        FileType::Directory
                    } else {
                        FileType::File
                    },
                ))
            })
            .collect()
    }

    async fn has_child_entry_with_client(
        &self,
        client: &tokio_postgres::Client,
        parent: &VirtualPath,
    ) -> Result<bool, FilesystemError> {
        let pattern = child_path_like_pattern(parent);
        let row = client
            .query_opt(
                "SELECT 1 FROM root_filesystem_entries WHERE path LIKE $1 ESCAPE '!' LIMIT 1",
                &[&pattern],
            )
            .await
            .map_err(|error| db_error(parent.clone(), FilesystemOperation::Stat, error))?;
        Ok(row.is_some())
    }

    async fn current_version_with_client(
        &self,
        client: &tokio_postgres::Client,
        path: &VirtualPath,
    ) -> Result<Option<RecordVersion>, FilesystemError> {
        let row = client
            .query_opt(
                "SELECT version FROM root_filesystem_entries WHERE path = $1 AND is_dir = FALSE",
                &[&path.as_str()],
            )
            .await
            .map_err(|error| db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        Ok(row.map(|row| {
            let version: i64 = row.get("version");
            RecordVersion::from_backend(version.max(0) as u64)
        }))
    }
}

#[cfg(feature = "postgres")]
fn build_entry(
    path: &VirtualPath,
    body: Vec<u8>,
    content_type_raw: String,
    kind_raw: Option<String>,
    indexed_value: serde_json::Value,
) -> Result<Entry, FilesystemError> {
    let content_type = ContentType::new(content_type_raw).map_err(FilesystemError::Contract)?;
    let kind = kind_raw
        .map(RecordKind::new)
        .transpose()
        .map_err(FilesystemError::Contract)?;
    let indexed: BTreeMap<IndexKey, IndexValue> = if indexed_value.is_null() {
        BTreeMap::new()
    } else {
        serde_json::from_value(indexed_value).map_err(|error| FilesystemError::Backend {
            path: path.clone(),
            operation: FilesystemOperation::ReadFile,
            reason: format!("failed to parse indexed projection: {error}"),
        })?
    };
    Ok(Entry {
        body,
        content_type,
        kind,
        indexed,
    })
}

#[cfg(feature = "postgres")]
const POSTGRES_ROOT_FILESYSTEM_SCHEMA: &str = concat!(
    include_str!("../../../migrations/V26__root_filesystem_entries.sql"),
    "\n",
    include_str!("../../../migrations/V27__root_filesystem_entries_directories.sql"),
    "\n",
    include_str!("../../../migrations/V28__root_filesystem_records.sql"),
);
