use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::VirtualPath;

use crate::db::{
    child_path_like_pattern, direct_children, directory_append_error, directory_write_error,
    is_not_found, libsql_db_error, not_found, system_time_from_unix_seconds, valid_engine_path,
    virtual_path_prefixes,
};
use crate::{
    BackendCapabilities, CasExpectation, ContentType, DirEntry, Entry, FileStat, FileType,
    FilesystemError, FilesystemOperation, Filter, IndexCapability, IndexKey, IndexKind, IndexSpec,
    IndexValue, Page, RecordKind, RecordVersion, RootFilesystem, TxnCapability, VersionedEntry,
};

#[cfg(feature = "libsql")]
/// libSQL-backed [`RootFilesystem`] storing file contents by virtual path.
pub struct LibSqlRootFilesystem {
    db: Arc<libsql::Database>,
}

#[cfg(feature = "libsql")]
impl LibSqlRootFilesystem {
    pub fn new(db: Arc<libsql::Database>) -> Self {
        Self { db }
    }

    pub async fn run_migrations(&self) -> Result<(), FilesystemError> {
        let conn = self.connect().await?;
        conn.execute_batch(LIBSQL_ROOT_FILESYSTEM_SCHEMA)
            .await
            .map_err(|error| {
                libsql_db_error(
                    valid_engine_path(),
                    FilesystemOperation::CreateDirAll,
                    error,
                )
            })?;
        ensure_libsql_root_is_dir_column(&conn).await?;
        ensure_libsql_records_columns(&conn).await?;
        ensure_libsql_index_specs_table(&conn).await?;
        Ok(())
    }

    async fn connect(&self) -> Result<libsql::Connection, FilesystemError> {
        let conn = self
            .db
            .connect()
            .map_err(|error| FilesystemError::Backend {
                path: valid_engine_path(),
                operation: FilesystemOperation::Stat,
                reason: error.to_string(),
            })?;
        conn.query("PRAGMA busy_timeout = 5000", ())
            .await
            .map_err(|error| {
                libsql_db_error(valid_engine_path(), FilesystemOperation::Stat, error)
            })?;
        Ok(conn)
    }
}

#[cfg(feature = "libsql")]
#[async_trait]
impl RootFilesystem for LibSqlRootFilesystem {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            read: true,
            write: true,
            append: true,
            list: true,
            stat: true,
            delete: true,
            records: true,
            // Native query over indexed projection with Filter::Eq/PrefixOn/
            // Range/And/Or; ensure_index materializes expression indexes on
            // json_extract(indexed, '$.key').
            query: true,
            index: IndexCapability {
                exact: true,
                prefix: true,
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
        // Reject writes that would clobber a directory or a path that has
        // children (mirrors `write_file` semantics so legacy and new ops
        // stay consistent).
        if matches!(
            self.exact_entry(path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry(path).await?
        {
            return Err(directory_write_error(path.clone()));
        }
        let indexed_json =
            serde_json::to_string(&entry.indexed).map_err(|error| FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::WriteFile,
                reason: format!("failed to serialize indexed projection: {error}"),
            })?;
        let kind_str = entry.kind.as_ref().map(|k| k.as_str().to_string());
        let content_type_str = entry.content_type.as_str().to_string();
        let body = entry.body;

        match cas {
            CasExpectation::Absent => {
                let conn = self.connect().await?;
                let rows = conn
                    .execute(
                        r#"
                        INSERT INTO root_filesystem_entries
                            (path, contents, is_dir, content_type, kind, indexed, version, updated_at)
                        VALUES (?1, ?2, 0, ?3, ?4, ?5, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                        ON CONFLICT (path) DO NOTHING
                        "#,
                        libsql::params![
                            path.as_str(),
                            libsql::Value::Blob(body),
                            content_type_str,
                            kind_str,
                            indexed_json,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        libsql_db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                if rows == 0 {
                    let found = self.current_version(path).await?;
                    return Err(FilesystemError::VersionMismatch {
                        path: path.clone(),
                        expected: None,
                        found,
                    });
                }
                Ok(RecordVersion::from_backend(1))
            }
            CasExpectation::Version(expected) => {
                let conn = self.connect().await?;
                let expected_raw = expected.get() as i64;
                let rows = conn
                    .execute(
                        r#"
                        UPDATE root_filesystem_entries
                        SET contents = ?1,
                            content_type = ?2,
                            kind = ?3,
                            indexed = ?4,
                            version = version + 1,
                            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        WHERE path = ?5 AND is_dir = 0 AND version = ?6
                        "#,
                        libsql::params![
                            libsql::Value::Blob(body),
                            content_type_str,
                            kind_str,
                            indexed_json,
                            path.as_str(),
                            expected_raw,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        libsql_db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                if rows == 0 {
                    let found = self.current_version(path).await?;
                    return Err(FilesystemError::VersionMismatch {
                        path: path.clone(),
                        expected: Some(expected),
                        found,
                    });
                }
                Ok(expected.next())
            }
            CasExpectation::Any => {
                let conn = self.connect().await?;
                let rows = conn
                    .execute(
                        r#"
                        INSERT INTO root_filesystem_entries
                            (path, contents, is_dir, content_type, kind, indexed, version, updated_at)
                        VALUES (?1, ?2, 0, ?3, ?4, ?5, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                        ON CONFLICT (path) DO UPDATE SET
                            contents = excluded.contents,
                            content_type = excluded.content_type,
                            kind = excluded.kind,
                            indexed = excluded.indexed,
                            version = root_filesystem_entries.version + 1,
                            updated_at = excluded.updated_at
                        WHERE root_filesystem_entries.is_dir = 0
                        "#,
                        libsql::params![
                            path.as_str(),
                            libsql::Value::Blob(body),
                            content_type_str,
                            kind_str,
                            indexed_json,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        libsql_db_error(path.clone(), FilesystemOperation::WriteFile, error)
                    })?;
                if rows == 0 {
                    return Err(directory_write_error(path.clone()));
                }
                let version =
                    self.current_version(path)
                        .await?
                        .ok_or_else(|| FilesystemError::Backend {
                            path: path.clone(),
                            operation: FilesystemOperation::WriteFile,
                            reason: "put succeeded but version lookup found no row".to_string(),
                        })?;
                Ok(version)
            }
        }
    }

    async fn get(&self, path: &VirtualPath) -> Result<Option<VersionedEntry>, FilesystemError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                r#"
                SELECT contents, is_dir, content_type, kind, indexed, version
                FROM root_filesystem_entries
                WHERE path = ?1
                "#,
                libsql::params![path.as_str()],
            )
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let Some(row) = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?
        else {
            return Ok(None);
        };
        let is_dir: i64 = row
            .get(1)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        if is_dir != 0 {
            // Directories are not addressable as Entries.
            return Ok(None);
        }
        let body: Vec<u8> = row
            .get(0)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let content_type_raw: String = row
            .get(2)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let kind_raw: Option<String> = row.get(3).ok();
        let indexed_raw: String = row
            .get(4)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let version_raw: i64 = row
            .get(5)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let entry = build_entry(path, body, content_type_raw, kind_raw, indexed_raw)?;
        Ok(Some(VersionedEntry {
            entry,
            version: RecordVersion::from_backend(version_raw.max(0) as u64),
        }))
    }

    async fn ensure_index(
        &self,
        path: &VirtualPath,
        spec: &IndexSpec,
    ) -> Result<(), FilesystemError> {
        // Only Exact and Prefix index kinds are supported on the SQL backends
        // in this port. FTS / Vector live behind their own follow-up port.
        let kind_str = match &spec.kind {
            IndexKind::Exact => "exact".to_string(),
            IndexKind::Prefix => "prefix".to_string(),
            IndexKind::Fts | IndexKind::Vector { .. } => {
                return Err(FilesystemError::Unsupported {
                    path: path.clone(),
                    operation: FilesystemOperation::EnsureIndex,
                });
            }
        };
        if spec.keys.is_empty() {
            return Err(FilesystemError::IndexConflict {
                path: path.clone(),
                name: spec.name.clone(),
                reason: "spec must declare at least one key".to_string(),
            });
        }
        let keys_json = serde_json::to_string(
            &spec
                .keys
                .iter()
                .map(|k| k.as_str().to_string())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| FilesystemError::Backend {
            path: path.clone(),
            operation: FilesystemOperation::EnsureIndex,
            reason: format!("failed to serialize index keys: {error}"),
        })?;

        let conn = self.connect().await?;
        // Conflict check: idempotent if same spec already declared, else
        // IndexConflict.
        let mut rows = conn
            .query(
                "SELECT keys, kind FROM root_filesystem_index_specs WHERE prefix = ?1 AND name = ?2",
                libsql::params![path.as_str(), spec.name.as_str()],
            )
            .await
            .map_err(|error| {
                libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error)
            })?;
        if let Some(row) = rows.next().await.map_err(|error| {
            libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error)
        })? {
            let existing_keys: String = row.get(0).map_err(|error| {
                libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error)
            })?;
            let existing_kind: String = row.get(1).map_err(|error| {
                libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error)
            })?;
            if existing_keys != keys_json || existing_kind != kind_str {
                return Err(FilesystemError::IndexConflict {
                    path: path.clone(),
                    name: spec.name.clone(),
                    reason: "spec already declared with different keys or kind".to_string(),
                });
            }
            return Ok(());
        }
        drop(rows);

        // Record the spec then materialize a SQL expression index on the
        // declared keys. The index is global on the table; queries route
        // by path-prefix in the WHERE clause and the planner can still use
        // this index for filter predicates.
        conn.execute(
            "INSERT INTO root_filesystem_index_specs (prefix, name, keys, kind) VALUES (?1, ?2, ?3, ?4)",
            libsql::params![
                path.as_str(),
                spec.name.as_str(),
                keys_json.clone(),
                kind_str,
            ],
        )
        .await
        .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error))?;

        let index_name = sql_index_name(path.as_str(), spec.name.as_str());
        let expressions: Vec<String> = spec
            .keys
            .iter()
            .map(|k| format!("json_extract(indexed, '$.{}')", k.as_str()))
            .collect();
        let ddl = format!(
            "CREATE INDEX IF NOT EXISTS {index_name} ON root_filesystem_entries ({})",
            expressions.join(", ")
        );
        conn.execute(&ddl, ()).await.map_err(|error| {
            libsql_db_error(path.clone(), FilesystemOperation::EnsureIndex, error)
        })?;
        Ok(())
    }

    async fn query(
        &self,
        path: &VirtualPath,
        filter: &Filter,
        page: Page,
    ) -> Result<Vec<VersionedEntry>, FilesystemError> {
        let mut params: Vec<libsql::Value> = vec![libsql::Value::Text(path.as_str().to_string())];
        let prefix_pattern = format!("{}/%", path.as_str());
        params.push(libsql::Value::Text(escape_like_pattern(&prefix_pattern)));

        let mut conditions = String::new();
        translate_filter(path, filter, &mut conditions, &mut params)?;

        let mut sql = String::from(
            "SELECT path, contents, content_type, kind, indexed, version \
             FROM root_filesystem_entries \
             WHERE is_dir = 0 AND (path = ?1 OR path LIKE ?2 ESCAPE '!')",
        );
        if !conditions.is_empty() {
            sql.push_str(" AND ");
            sql.push_str(&conditions);
        }
        sql.push_str(" ORDER BY path LIMIT ? OFFSET ?");
        params.push(libsql::Value::Integer(
            page.limit.min(crate::Page::MAX_LIMIT) as i64,
        ));
        params.push(libsql::Value::Integer(page.offset as i64));

        let conn = self.connect().await?;
        let mut rows = conn
            .query(&sql, params)
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Query, error))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Query, error))?
        {
            let row_path: String = row.get(0).map_err(|error| {
                libsql_db_error(path.clone(), FilesystemOperation::Query, error)
            })?;
            let row_path = VirtualPath::new(row_path)?;
            let body: Vec<u8> = row.get(1).map_err(|error| {
                libsql_db_error(row_path.clone(), FilesystemOperation::Query, error)
            })?;
            let content_type_raw: String = row.get(2).map_err(|error| {
                libsql_db_error(row_path.clone(), FilesystemOperation::Query, error)
            })?;
            let kind_raw: Option<String> = row.get(3).ok();
            let indexed_raw: String = row.get(4).map_err(|error| {
                libsql_db_error(row_path.clone(), FilesystemOperation::Query, error)
            })?;
            let version_raw: i64 = row.get(5).map_err(|error| {
                libsql_db_error(row_path.clone(), FilesystemOperation::Query, error)
            })?;
            let entry = build_entry(&row_path, body, content_type_raw, kind_raw, indexed_raw)?;
            out.push(VersionedEntry {
                entry,
                version: RecordVersion::from_backend(version_raw.max(0) as u64),
            });
        }
        Ok(out)
    }

    async fn read_file(&self, path: &VirtualPath) -> Result<Vec<u8>, FilesystemError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT contents, is_dir FROM root_filesystem_entries WHERE path = ?1",
                libsql::params![path.as_str()],
            )
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let Some(row) = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?
        else {
            return Err(not_found(path.clone(), FilesystemOperation::ReadFile));
        };
        let is_dir: i64 = row
            .get(1)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        if is_dir != 0 {
            return Err(FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::ReadFile,
                reason: "is a directory".to_string(),
            });
        }
        row.get(0)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))
    }

    async fn write_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        if matches!(
            self.exact_entry(path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry(path).await?
        {
            return Err(directory_write_error(path.clone()));
        }
        let conn = self.connect().await?;
        // PR #3660 reviewer fix: legacy write_file must also reset the
        // record metadata (content_type / kind / indexed) and bump the
        // version, otherwise a get() after a write_file-overwrite of a
        // previously record-shaped entry returns stale metadata. Treat
        // legacy writes as opaque-file entries: kind=NULL, indexed='{}',
        // content_type=application/octet-stream, version bumped from the
        // current row's version (or 1 for new entries).
        let rows = conn
            .execute(
                r#"
                INSERT INTO root_filesystem_entries
                    (path, contents, is_dir, content_type, kind, indexed, version, updated_at)
                VALUES (?1, ?2, 0, 'application/octet-stream', NULL, '{}', 1,
                        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                ON CONFLICT (path) DO UPDATE SET
                    contents = excluded.contents,
                    is_dir = 0,
                    content_type = excluded.content_type,
                    kind = excluded.kind,
                    indexed = excluded.indexed,
                    version = root_filesystem_entries.version + 1,
                    updated_at = excluded.updated_at
                WHERE root_filesystem_entries.is_dir = 0
                "#,
                libsql::params![path.as_str(), libsql::Value::Blob(bytes.to_vec())],
            )
            .await
            .map_err(|error| {
                libsql_db_error(path.clone(), FilesystemOperation::WriteFile, error)
            })?;
        if rows == 0 {
            return Err(directory_write_error(path.clone()));
        }
        Ok(())
    }

    async fn append_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        if matches!(
            self.exact_entry(path).await?,
            Some((_, FileType::Directory, _))
        ) || self.has_child_entry(path).await?
        {
            return Err(directory_append_error(path.clone()));
        }
        let conn = self.connect().await?;
        // PR #3660 reviewer fix: same metadata-reset concern as write_file.
        // Append also resets kind/indexed/content_type to opaque-file
        // defaults — appending bytes onto a previously record-shaped
        // entry was always a category error, and we surface that by
        // clearing the schema metadata rather than leaving it stale.
        // TODO(reborn): append rewrites the whole DB row. Do not use this
        // path for high-volume JSONL/event streams; route those through
        // typed event stores or append-capable artifact backends.
        conn.execute(
            r#"
            INSERT INTO root_filesystem_entries
                (path, contents, is_dir, content_type, kind, indexed, version, updated_at)
            VALUES (?1, ?2, 0, 'application/octet-stream', NULL, '{}', 1,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT (path) DO UPDATE SET
                contents = CAST(root_filesystem_entries.contents || excluded.contents AS BLOB),
                is_dir = 0,
                content_type = excluded.content_type,
                kind = excluded.kind,
                indexed = excluded.indexed,
                version = root_filesystem_entries.version + 1,
                updated_at = excluded.updated_at
            "#,
            libsql::params![path.as_str(), libsql::Value::Blob(bytes.to_vec())],
        )
        .await
        .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::AppendFile, error))?;
        Ok(())
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        let exact_entry = self.exact_entry(path).await?;
        if matches!(exact_entry, Some((_, FileType::File, _))) {
            return Err(FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::ListDir,
                reason: "not a directory".to_string(),
            });
        }
        let rows = self
            .child_entries(path, FilesystemOperation::ListDir)
            .await?;
        let children = direct_children(path, rows);
        if matches!(exact_entry, Some((_, FileType::Directory, _))) && is_not_found(&children) {
            return Ok(Vec::new());
        }
        children
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        if let Some((len, file_type, modified)) = self.exact_entry(path).await? {
            return Ok(FileStat {
                path: path.clone(),
                file_type,
                len,
                modified,
                sensitive: false,
            });
        }
        if self.has_child_entry(path).await? {
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
        let conn = self.connect().await?;
        let deleted = conn
            .execute(
                "DELETE FROM root_filesystem_entries WHERE path = ?1 OR path LIKE ?2 ESCAPE '!'",
                libsql::params![path.as_str(), child_path_like_pattern(path)],
            )
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Delete, error))?;
        if deleted == 0 {
            return Err(not_found(path.clone(), FilesystemOperation::Delete));
        }
        Ok(())
    }

    async fn create_dir_all(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let conn = self.connect().await?;
        let transaction = conn.transaction().await.map_err(|error| {
            libsql_db_error(path.clone(), FilesystemOperation::CreateDirAll, error)
        })?;
        for prefix in virtual_path_prefixes(path)? {
            let mut rows = transaction
                .query(
                    "SELECT is_dir FROM root_filesystem_entries WHERE path = ?1",
                    libsql::params![prefix.as_str()],
                )
                .await
                .map_err(|error| {
                    libsql_db_error(prefix.clone(), FilesystemOperation::CreateDirAll, error)
                })?;
            if let Some(row) = rows.next().await.map_err(|error| {
                libsql_db_error(prefix.clone(), FilesystemOperation::CreateDirAll, error)
            })? {
                let is_dir: i64 = row.get(0).map_err(|error| {
                    libsql_db_error(prefix.clone(), FilesystemOperation::CreateDirAll, error)
                })?;
                if is_dir == 0 {
                    return Err(FilesystemError::Backend {
                        path: prefix,
                        operation: FilesystemOperation::CreateDirAll,
                        reason: "file exists where directory is required".to_string(),
                    });
                }
            }
            transaction
                .execute(
                    r#"
                    INSERT INTO root_filesystem_entries (path, contents, is_dir, updated_at)
                    VALUES (?1, X'', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT (path) DO NOTHING
                    "#,
                    libsql::params![prefix.as_str()],
                )
                .await
                .map_err(|error| {
                    libsql_db_error(path.clone(), FilesystemOperation::CreateDirAll, error)
                })?;
        }
        transaction.commit().await.map_err(|error| {
            libsql_db_error(path.clone(), FilesystemOperation::CreateDirAll, error)
        })?;
        Ok(())
    }
}

#[cfg(feature = "libsql")]
async fn ensure_libsql_root_is_dir_column(
    conn: &libsql::Connection,
) -> Result<(), FilesystemError> {
    let mut rows = conn
        .query(
            "SELECT 1 FROM pragma_table_info('root_filesystem_entries') WHERE name = 'is_dir'",
            (),
        )
        .await
        .map_err(|error| {
            libsql_db_error(
                valid_engine_path(),
                FilesystemOperation::CreateDirAll,
                error,
            )
        })?;
    if rows
        .next()
        .await
        .map_err(|error| {
            libsql_db_error(
                valid_engine_path(),
                FilesystemOperation::CreateDirAll,
                error,
            )
        })?
        .is_some()
    {
        return Ok(());
    }
    conn.execute(
        "ALTER TABLE root_filesystem_entries ADD COLUMN is_dir INTEGER NOT NULL DEFAULT 0 CHECK (is_dir IN (0, 1))",
        (),
    )
    .await
    .map_err(|error| {
        libsql_db_error(
            valid_engine_path(),
            FilesystemOperation::CreateDirAll,
            error,
        )
    })?;
    Ok(())
}

#[cfg(feature = "libsql")]
impl LibSqlRootFilesystem {
    async fn exact_entry(
        &self,
        path: &VirtualPath,
    ) -> Result<Option<(u64, FileType, Option<std::time::SystemTime>)>, FilesystemError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT length(contents), is_dir, CAST(strftime('%s', updated_at) AS INTEGER) AS updated_at_epoch FROM root_filesystem_entries WHERE path = ?1",
                libsql::params![path.as_str()],
            )
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Stat, error))?;
        let row = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Stat, error))?;
        let Some(row) = row else { return Ok(None) };
        let len_raw: i64 = row
            .get(0)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Stat, error))?;
        let is_dir_raw: i64 = row
            .get(1)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Stat, error))?;
        let updated_at_epoch: i64 = row
            .get(2)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::Stat, error))?;
        let len = len_raw.max(0) as u64;
        let is_dir = is_dir_raw != 0;
        Ok(Some((
            if is_dir { 0 } else { len },
            if is_dir {
                FileType::Directory
            } else {
                FileType::File
            },
            system_time_from_unix_seconds(updated_at_epoch),
        )))
    }

    async fn child_entries(
        &self,
        parent: &VirtualPath,
        operation: FilesystemOperation,
    ) -> Result<Vec<(VirtualPath, u64, FileType)>, FilesystemError> {
        let conn = self.connect().await?;
        let pattern = child_path_like_pattern(parent);
        let mut rows = conn
            .query(
                "SELECT path, length(contents), is_dir FROM root_filesystem_entries WHERE path LIKE ?1 ESCAPE '!' ORDER BY path",
                libsql::params![pattern],
            )
            .await
            .map_err(|error| libsql_db_error(parent.clone(), operation, error))?;
        let mut paths = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(parent.clone(), operation, error))?
        {
            let path: String = row
                .get(0)
                .map_err(|error| libsql_db_error(parent.clone(), operation, error))?;
            let len_raw: i64 = row
                .get(1)
                .map_err(|error| libsql_db_error(parent.clone(), operation, error))?;
            let is_dir_raw: i64 = row
                .get(2)
                .map_err(|error| libsql_db_error(parent.clone(), operation, error))?;
            let len = len_raw.max(0) as u64;
            let is_dir = is_dir_raw != 0;
            paths.push((
                VirtualPath::new(path)?,
                if is_dir { 0 } else { len },
                if is_dir {
                    FileType::Directory
                } else {
                    FileType::File
                },
            ));
        }
        Ok(paths)
    }

    async fn has_child_entry(&self, parent: &VirtualPath) -> Result<bool, FilesystemError> {
        let conn = self.connect().await?;
        let pattern = child_path_like_pattern(parent);
        let mut rows = conn
            .query(
                "SELECT 1 FROM root_filesystem_entries WHERE path LIKE ?1 ESCAPE '!' LIMIT 1",
                libsql::params![pattern],
            )
            .await
            .map_err(|error| libsql_db_error(parent.clone(), FilesystemOperation::Stat, error))?;
        Ok(rows
            .next()
            .await
            .map_err(|error| libsql_db_error(parent.clone(), FilesystemOperation::Stat, error))?
            .is_some())
    }

    async fn current_version(
        &self,
        path: &VirtualPath,
    ) -> Result<Option<RecordVersion>, FilesystemError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT version FROM root_filesystem_entries WHERE path = ?1 AND is_dir = 0",
                libsql::params![path.as_str()],
            )
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let Some(row) = rows
            .next()
            .await
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?
        else {
            return Ok(None);
        };
        let version: i64 = row
            .get(0)
            .map_err(|error| libsql_db_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        Ok(Some(RecordVersion::from_backend(version.max(0) as u64)))
    }
}

#[cfg(feature = "libsql")]
fn build_entry(
    path: &VirtualPath,
    body: Vec<u8>,
    content_type_raw: String,
    kind_raw: Option<String>,
    indexed_raw: String,
) -> Result<Entry, FilesystemError> {
    let content_type = ContentType::new(content_type_raw).map_err(FilesystemError::Contract)?;
    let kind = kind_raw
        .map(RecordKind::new)
        .transpose()
        .map_err(FilesystemError::Contract)?;
    let indexed: BTreeMap<IndexKey, IndexValue> = if indexed_raw.is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_str(&indexed_raw).map_err(|error| FilesystemError::Backend {
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

#[cfg(feature = "libsql")]
async fn ensure_libsql_records_columns(conn: &libsql::Connection) -> Result<(), FilesystemError> {
    add_column_if_missing(
        conn,
        "content_type",
        "ALTER TABLE root_filesystem_entries ADD COLUMN content_type TEXT NOT NULL DEFAULT 'application/octet-stream'",
    )
    .await?;
    add_column_if_missing(
        conn,
        "kind",
        "ALTER TABLE root_filesystem_entries ADD COLUMN kind TEXT",
    )
    .await?;
    add_column_if_missing(
        conn,
        "indexed",
        "ALTER TABLE root_filesystem_entries ADD COLUMN indexed TEXT NOT NULL DEFAULT '{}'",
    )
    .await?;
    add_column_if_missing(
        conn,
        "version",
        "ALTER TABLE root_filesystem_entries ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
    )
    .await?;
    Ok(())
}

#[cfg(feature = "libsql")]
async fn ensure_libsql_index_specs_table(conn: &libsql::Connection) -> Result<(), FilesystemError> {
    conn.execute_batch(LIBSQL_INDEX_SPECS_SCHEMA)
        .await
        .map_err(|error| {
            libsql_db_error(valid_engine_path(), FilesystemOperation::EnsureIndex, error)
        })?;
    Ok(())
}

/// Build a deterministic SQL index identifier from a mount prefix + spec name.
///
/// IndexKey/IndexName are validated to be simple identifiers (no path
/// separators, whitespace, or control chars), so the prefix's slashes are
/// the only non-identifier characters we need to replace. Length is bounded
/// — Postgres caps at 63, SQLite is more permissive — so we truncate after
/// sanitisation. Collisions across mounts are tolerable: distinct
/// `(prefix, name)` pairs share an index when their sanitized forms match,
/// and the index is still correct (the planner just sees a wider index).
#[cfg(feature = "libsql")]
fn sql_index_name(prefix: &str, name: &str) -> String {
    let prefix_clean: String = prefix
        .trim_matches('/')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let raw = format!("idx_rfs_{prefix_clean}_{name}");
    // Identifier length budget chosen to satisfy Postgres' 63-char cap so
    // libsql and postgres can share the same naming logic in future refactors.
    if raw.len() > 62 {
        let cutoff = raw
            .char_indices()
            .nth(62)
            .map(|(i, _)| i)
            .unwrap_or(raw.len());
        raw[..cutoff].to_string()
    } else {
        raw
    }
}

#[cfg(feature = "libsql")]
fn escape_like_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' if chars.peek().is_some() => out.push_str("!%"),
            '_' => out.push_str("!_"),
            '!' => out.push_str("!!"),
            other => out.push(other),
        }
    }
    out
}

/// Translate a [`Filter`] tree into a libsql WHERE-clause fragment, appending
/// bound parameters to `params` in left-to-right order. The fragment is
/// wrapped in parentheses unless empty.
#[cfg(feature = "libsql")]
fn translate_filter(
    path: &VirtualPath,
    filter: &Filter,
    out: &mut String,
    params: &mut Vec<libsql::Value>,
) -> Result<(), FilesystemError> {
    match filter {
        Filter::All => Ok(()),
        Filter::Eq { key, value } => {
            let placeholder = bind_index_value(path, value, params)?;
            out.push_str(&format!(
                "(json_extract(indexed, '$.{}') = ?{})",
                key.as_str(),
                placeholder
            ));
            Ok(())
        }
        Filter::PrefixOn { key, value } => {
            let IndexValue::Text(prefix_value) = value else {
                return Err(FilesystemError::Unsupported {
                    path: path.clone(),
                    operation: FilesystemOperation::Query,
                });
            };
            let escaped = escape_like_pattern(prefix_value);
            params.push(libsql::Value::Text(format!("{escaped}%")));
            out.push_str(&format!(
                "(json_extract(indexed, '$.{}') LIKE ?{} ESCAPE '!')",
                key.as_str(),
                params.len()
            ));
            Ok(())
        }
        Filter::Range { key, lo, hi } => {
            let lo_idx = bind_index_value(path, lo, params)?;
            let hi_idx = bind_index_value(path, hi, params)?;
            out.push_str(&format!(
                "(json_extract(indexed, '$.{}') BETWEEN ?{} AND ?{})",
                key.as_str(),
                lo_idx,
                hi_idx
            ));
            Ok(())
        }
        Filter::And(children) => translate_compound(path, children, " AND ", out, params),
        Filter::Or(children) => translate_compound(path, children, " OR ", out, params),
    }
}

#[cfg(feature = "libsql")]
fn translate_compound(
    path: &VirtualPath,
    children: &[Filter],
    joiner: &str,
    out: &mut String,
    params: &mut Vec<libsql::Value>,
) -> Result<(), FilesystemError> {
    if children.is_empty() {
        return Ok(());
    }
    out.push('(');
    let mut first = true;
    for child in children {
        let mut sub = String::new();
        translate_filter(path, child, &mut sub, params)?;
        if sub.is_empty() {
            continue;
        }
        if !first {
            out.push_str(joiner);
        }
        out.push_str(&sub);
        first = false;
    }
    out.push(')');
    Ok(())
}

#[cfg(feature = "libsql")]
fn bind_index_value(
    path: &VirtualPath,
    value: &IndexValue,
    params: &mut Vec<libsql::Value>,
) -> Result<usize, FilesystemError> {
    let bound = match value {
        IndexValue::Text(s) => libsql::Value::Text(s.clone()),
        IndexValue::I64(n) => libsql::Value::Integer(*n),
        IndexValue::Bool(b) => libsql::Value::Integer(i64::from(*b)),
        IndexValue::Bytes(_) => {
            return Err(FilesystemError::Unsupported {
                path: path.clone(),
                operation: FilesystemOperation::Query,
            });
        }
    };
    params.push(bound);
    Ok(params.len())
}

#[cfg(feature = "libsql")]
async fn add_column_if_missing(
    conn: &libsql::Connection,
    column: &str,
    ddl: &str,
) -> Result<(), FilesystemError> {
    let mut rows = conn
        .query(
            "SELECT 1 FROM pragma_table_info('root_filesystem_entries') WHERE name = ?1",
            libsql::params![column],
        )
        .await
        .map_err(|error| {
            libsql_db_error(
                valid_engine_path(),
                FilesystemOperation::CreateDirAll,
                error,
            )
        })?;
    if rows
        .next()
        .await
        .map_err(|error| {
            libsql_db_error(
                valid_engine_path(),
                FilesystemOperation::CreateDirAll,
                error,
            )
        })?
        .is_some()
    {
        return Ok(());
    }
    conn.execute(ddl, ()).await.map_err(|error| {
        libsql_db_error(
            valid_engine_path(),
            FilesystemOperation::CreateDirAll,
            error,
        )
    })?;
    Ok(())
}

#[cfg(feature = "libsql")]
const LIBSQL_ROOT_FILESYSTEM_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS root_filesystem_entries (
    path TEXT PRIMARY KEY,
    contents BLOB NOT NULL DEFAULT X'',
    is_dir INTEGER NOT NULL DEFAULT 0 CHECK (is_dir IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
-- The PRIMARY KEY on `path` already provides a unique index for equality
-- lookups, so no separate index is created.
"#;

#[cfg(feature = "libsql")]
const LIBSQL_INDEX_SPECS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS root_filesystem_index_specs (
    prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    keys TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (prefix, name)
);
"#;
