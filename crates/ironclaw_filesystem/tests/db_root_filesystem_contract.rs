#![cfg(any(feature = "libsql", feature = "postgres"))]

use ironclaw_filesystem::RootFilesystem;

#[cfg(feature = "postgres")]
use ironclaw_filesystem::PostgresRootFilesystem;
#[cfg(feature = "libsql")]
use ironclaw_filesystem::{
    CasExpectation, Entry, FileType, FilesystemError, FilesystemOperation, Filter, IndexKey,
    IndexKind, IndexName, IndexSpec, IndexValue, LibSqlRootFilesystem, Page, RecordKind,
};
#[cfg(feature = "libsql")]
use ironclaw_host_api::VirtualPath;

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_reads_writes_and_stats_files() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/engine/tenants/t1/users/u1/file.txt").unwrap();

    filesystem.write_file(&path, b"hello db fs").await.unwrap();

    assert_eq!(filesystem.read_file(&path).await.unwrap(), b"hello db fs");
    let stat = filesystem.stat(&path).await.unwrap();
    assert_eq!(stat.path, path);
    assert_eq!(stat.file_type, FileType::File);
    assert_eq!(stat.len, 11);
    assert!(stat.modified.is_some());
    assert!(!stat.sensitive);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_lists_direct_children_sorted_with_virtual_paths() {
    let filesystem = libsql_root().await;
    filesystem
        .write_file(
            &VirtualPath::new("/engine/tenants/t1/users/u1/zeta.txt").unwrap(),
            b"z",
        )
        .await
        .unwrap();
    filesystem
        .write_file(
            &VirtualPath::new("/engine/tenants/t1/users/u1/alpha.txt").unwrap(),
            b"a",
        )
        .await
        .unwrap();
    filesystem
        .write_file(
            &VirtualPath::new("/engine/tenants/t1/users/u1/nested/file.txt").unwrap(),
            b"nested",
        )
        .await
        .unwrap();

    let entries = filesystem
        .list_dir(&VirtualPath::new("/engine/tenants/t1/users/u1").unwrap())
        .await
        .unwrap();

    let names: Vec<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, vec!["alpha.txt", "nested", "zeta.txt"]);

    let paths: Vec<_> = entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "/engine/tenants/t1/users/u1/alpha.txt",
            "/engine/tenants/t1/users/u1/nested",
            "/engine/tenants/t1/users/u1/zeta.txt",
        ]
    );
    assert_eq!(entries[1].file_type, FileType::Directory);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_appends_deletes_and_creates_directories() {
    let filesystem = libsql_root().await;
    let dir = VirtualPath::new("/engine/tenants/t1/users/u1/logs").unwrap();
    let path = VirtualPath::new("/engine/tenants/t1/users/u1/logs/events.jsonl").unwrap();

    filesystem.create_dir_all(&dir).await.unwrap();
    assert_eq!(
        filesystem.stat(&dir).await.unwrap().file_type,
        FileType::Directory
    );
    assert!(filesystem.list_dir(&dir).await.unwrap().is_empty());

    filesystem.append_file(&path, b"one\n").await.unwrap();
    filesystem.append_file(&path, b"two\n").await.unwrap();
    assert_eq!(filesystem.read_file(&path).await.unwrap(), b"one\ntwo\n");

    filesystem.delete(&path).await.unwrap();
    let err = filesystem.read_file(&path).await.unwrap_err();
    assert!(matches!(
        err,
        FilesystemError::NotFound {
            operation: FilesystemOperation::ReadFile,
            ..
        }
    ));

    let err = filesystem.delete(&path).await.unwrap_err();
    assert!(matches!(
        err,
        FilesystemError::NotFound {
            operation: FilesystemOperation::Delete,
            ..
        }
    ));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_overwrites_existing_file() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/memory/tenants/t1/users/u1/facts.md").unwrap();

    filesystem.write_file(&path, b"first").await.unwrap();
    filesystem.write_file(&path, b"second").await.unwrap();

    assert_eq!(filesystem.read_file(&path).await.unwrap(), b"second");
    assert_eq!(filesystem.stat(&path).await.unwrap().len, 6);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_write_file_rejects_existing_directory() {
    let filesystem = libsql_root().await;
    let dir = VirtualPath::new("/engine/tenants/t1/users/u1/logs").unwrap();
    let child = VirtualPath::new("/engine/tenants/t1/users/u1/logs/events.jsonl").unwrap();

    filesystem.create_dir_all(&dir).await.unwrap();
    filesystem.write_file(&child, b"one\n").await.unwrap();
    let err = filesystem.write_file(&dir, b"not a dir").await.unwrap_err();

    assert!(matches!(
        err,
        FilesystemError::Backend {
            operation: FilesystemOperation::WriteFile,
            ..
        }
    ));
    assert_eq!(
        filesystem.stat(&dir).await.unwrap().file_type,
        FileType::Directory
    );
    assert_eq!(filesystem.read_file(&child).await.unwrap(), b"one\n");
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_write_file_rejects_implicit_directory() {
    let filesystem = libsql_root().await;
    let dir = VirtualPath::new("/engine/tenants/t1/users/u1/nested").unwrap();
    let child = VirtualPath::new("/engine/tenants/t1/users/u1/nested/file.txt").unwrap();

    filesystem.write_file(&child, b"child").await.unwrap();
    let err = filesystem.write_file(&dir, b"not a dir").await.unwrap_err();

    assert!(matches!(
        err,
        FilesystemError::Backend {
            operation: FilesystemOperation::WriteFile,
            ..
        }
    ));
    assert_eq!(
        filesystem.stat(&dir).await.unwrap().file_type,
        FileType::Directory
    );
    assert_eq!(filesystem.read_file(&child).await.unwrap(), b"child");
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_append_file_rejects_implicit_directory() {
    let filesystem = libsql_root().await;
    let dir = VirtualPath::new("/engine/tenants/t1/users/u1/append-nested").unwrap();
    let child = VirtualPath::new("/engine/tenants/t1/users/u1/append-nested/file.txt").unwrap();

    filesystem.write_file(&child, b"child").await.unwrap();
    let err = filesystem
        .append_file(&dir, b"not a dir")
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        FilesystemError::Backend {
            operation: FilesystemOperation::AppendFile,
            ..
        }
    ));
    assert_eq!(
        filesystem.stat(&dir).await.unwrap().file_type,
        FileType::Directory
    );
    assert_eq!(filesystem.read_file(&child).await.unwrap(), b"child");
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_root_filesystem_fails_closed_for_missing_paths_without_host_paths() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/projects/missing.txt").unwrap();

    let err = filesystem.read_file(&path).await.unwrap_err();
    assert!(matches!(
        err,
        FilesystemError::NotFound {
            operation: FilesystemOperation::ReadFile,
            ..
        }
    ));
    let display = err.to_string();
    assert!(display.contains("/projects/missing.txt"));
    assert!(!display.contains("/tmp"));
    assert!(!display.contains(".db"));
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_root_filesystem_implements_root_filesystem_contract() {
    fn assert_root<T: RootFilesystem>() {}
    assert_root::<PostgresRootFilesystem>();
}

#[cfg(feature = "libsql")]
struct TestLibSqlRootFilesystem {
    filesystem: LibSqlRootFilesystem,
    _dir: tempfile::TempDir,
}

#[cfg(feature = "libsql")]
impl std::ops::Deref for TestLibSqlRootFilesystem {
    type Target = LibSqlRootFilesystem;

    fn deref(&self) -> &Self::Target {
        &self.filesystem
    }
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_native_put_get_round_trip_with_record_metadata() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/L1").unwrap();

    let kind = RecordKind::new("credential_lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    let status_key = IndexKey::new("status").unwrap();
    let entry = Entry::record(kind.clone(), &serde_json::json!({"hidden": true}))
        .unwrap()
        .with_indexed(scope_key.clone(), IndexValue::Text("acme".into()))
        .with_indexed(status_key.clone(), IndexValue::Text("active".into()));

    let version1 = filesystem
        .put(&path, entry, CasExpectation::Absent)
        .await
        .unwrap();
    assert_eq!(version1.get(), 1);

    let got = filesystem
        .get(&path)
        .await
        .unwrap()
        .expect("entry should be present");
    assert_eq!(got.version, version1);
    assert_eq!(got.entry.kind.as_ref(), Some(&kind));
    assert_eq!(got.entry.indexed.len(), 2);
    assert!(got.entry.indexed.contains_key(&scope_key));
    assert!(got.entry.indexed.contains_key(&status_key));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_native_put_cas_absent_rejects_existing_path() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/L2").unwrap();
    filesystem
        .put(&path, Entry::bytes(vec![1]), CasExpectation::Absent)
        .await
        .unwrap();
    let err = filesystem
        .put(&path, Entry::bytes(vec![2]), CasExpectation::Absent)
        .await
        .unwrap_err();
    assert!(matches!(err, FilesystemError::VersionMismatch { .. }));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_native_put_cas_version_advances_and_rejects_stale() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/L3").unwrap();
    let v1 = filesystem
        .put(&path, Entry::bytes(vec![1]), CasExpectation::Absent)
        .await
        .unwrap();
    let v2 = filesystem
        .put(&path, Entry::bytes(vec![2]), CasExpectation::Version(v1))
        .await
        .unwrap();
    assert!(v2 > v1);
    // Stale version rejected.
    let err = filesystem
        .put(&path, Entry::bytes(vec![3]), CasExpectation::Version(v1))
        .await
        .unwrap_err();
    assert!(matches!(err, FilesystemError::VersionMismatch { .. }));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_native_put_cas_any_increments_existing_version() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/L4").unwrap();
    let v1 = filesystem
        .put(&path, Entry::bytes(vec![1]), CasExpectation::Absent)
        .await
        .unwrap();
    let v2 = filesystem
        .put(&path, Entry::bytes(vec![2]), CasExpectation::Any)
        .await
        .unwrap();
    assert_eq!(v2.get(), v1.get() + 1);
    let got = filesystem.get(&path).await.unwrap().unwrap();
    assert_eq!(got.version, v2);
    assert_eq!(got.entry.body, vec![2]);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_get_returns_none_for_missing_path() {
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/missing").unwrap();
    assert!(filesystem.get(&path).await.unwrap().is_none());
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_write_file_after_put_resets_record_metadata_and_bumps_version() {
    // PR #3660 reviewer fix: legacy write_file/append_file used to update
    // only `contents`/`is_dir`/`updated_at`, leaving stale `kind`,
    // `indexed`, `content_type`, and `version` from a prior put. A
    // subsequent get() would then return a versioned-entry whose
    // metadata didn't match the bytes. The fix clears schema metadata
    // and bumps the version on every legacy write.
    let filesystem = libsql_root().await;
    let path = VirtualPath::new("/secrets/leases/STALE").unwrap();
    let kind = RecordKind::new("credential_lease").unwrap();
    let scope = IndexKey::new("scope").unwrap();
    let record_entry = Entry::record(kind, &serde_json::json!({"k": 1}))
        .unwrap()
        .with_indexed(scope, IndexValue::Text("acme".into()));

    let v1 = filesystem
        .put(&path, record_entry, CasExpectation::Absent)
        .await
        .unwrap();

    // Legacy write overwrites the entry with opaque bytes.
    filesystem.write_file(&path, b"opaque").await.unwrap();

    let got = filesystem.get(&path).await.unwrap().unwrap();
    // Metadata cleared: kind=None, indexed empty. Version bumped from v1.
    assert!(got.entry.kind.is_none());
    assert!(got.entry.indexed.is_empty());
    assert_eq!(got.entry.body, b"opaque");
    assert!(got.version > v1);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_ensure_index_is_idempotent_and_conflict_aware() {
    let filesystem = libsql_root().await;
    let prefix = VirtualPath::new("/secrets/leases").unwrap();
    let name = IndexName::new("by_scope_status").unwrap();
    let keys = vec![
        IndexKey::new("scope").unwrap(),
        IndexKey::new("status").unwrap(),
    ];
    let spec_exact = IndexSpec::new(name.clone(), keys.clone(), IndexKind::Exact);
    let spec_prefix = IndexSpec::new(name, keys, IndexKind::Prefix);

    filesystem.ensure_index(&prefix, &spec_exact).await.unwrap();
    // Re-declaring same spec is idempotent.
    filesystem.ensure_index(&prefix, &spec_exact).await.unwrap();
    // Declaring a different kind under the same name is a conflict.
    let err = filesystem
        .ensure_index(&prefix, &spec_prefix)
        .await
        .unwrap_err();
    assert!(matches!(err, FilesystemError::IndexConflict { .. }));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_ensure_index_rejects_fts_and_vector_kinds() {
    let filesystem = libsql_root().await;
    let prefix = VirtualPath::new("/memory").unwrap();
    let spec = IndexSpec::new(
        IndexName::new("by_chunk").unwrap(),
        vec![IndexKey::new("chunk_id").unwrap()],
        IndexKind::Fts,
    );
    let err = filesystem.ensure_index(&prefix, &spec).await.unwrap_err();
    assert!(matches!(err, FilesystemError::Unsupported { .. }));
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_query_filters_on_indexed_projection() {
    let filesystem = libsql_root().await;
    let kind = RecordKind::new("lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    let status_key = IndexKey::new("status").unwrap();
    let prefix = VirtualPath::new("/secrets/leases").unwrap();
    let spec = IndexSpec::new(
        IndexName::new("by_scope_status").unwrap(),
        vec![scope_key.clone(), status_key.clone()],
        IndexKind::Exact,
    );
    filesystem.ensure_index(&prefix, &spec).await.unwrap();

    for (path, scope, status) in [
        ("/secrets/leases/A", "acme", "active"),
        ("/secrets/leases/B", "acme", "revoked"),
        ("/secrets/leases/C", "globex", "active"),
        ("/secrets/leases/D", "acme", "active"),
    ] {
        let entry = Entry::record(kind.clone(), &serde_json::json!({}))
            .unwrap()
            .with_indexed(scope_key.clone(), IndexValue::Text(scope.into()))
            .with_indexed(status_key.clone(), IndexValue::Text(status.into()));
        filesystem
            .put(
                &VirtualPath::new(path).unwrap(),
                entry,
                CasExpectation::Absent,
            )
            .await
            .unwrap();
    }

    let results = filesystem
        .query(
            &prefix,
            &Filter::And(vec![
                Filter::Eq {
                    key: scope_key,
                    value: IndexValue::Text("acme".into()),
                },
                Filter::Eq {
                    key: status_key,
                    value: IndexValue::Text("active".into()),
                },
            ]),
            Page::default(),
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    let mut paths: Vec<String> = results
        .iter()
        .map(|v| String::from_utf8_lossy(&v.entry.body).into_owned())
        .collect();
    paths.sort();
    // Both matching rows have empty bodies; verify by re-reading the
    // indexed projection on each result.
    let acme_active_count = results
        .iter()
        .filter(|v| {
            v.entry.indexed.get(&IndexKey::new("scope").unwrap())
                == Some(&IndexValue::Text("acme".into()))
                && v.entry.indexed.get(&IndexKey::new("status").unwrap())
                    == Some(&IndexValue::Text("active".into()))
        })
        .count();
    assert_eq!(acme_active_count, 2);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_query_prefix_filter_matches_text_prefix() {
    let filesystem = libsql_root().await;
    let kind = RecordKind::new("lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    let prefix = VirtualPath::new("/secrets/leases").unwrap();

    for (path, scope) in [
        ("/secrets/leases/X", "tenant:acme/u/1"),
        ("/secrets/leases/Y", "tenant:acme/u/2"),
        ("/secrets/leases/Z", "tenant:globex/u/1"),
    ] {
        let entry = Entry::record(kind.clone(), &serde_json::json!({}))
            .unwrap()
            .with_indexed(scope_key.clone(), IndexValue::Text(scope.into()));
        filesystem
            .put(
                &VirtualPath::new(path).unwrap(),
                entry,
                CasExpectation::Absent,
            )
            .await
            .unwrap();
    }

    let results = filesystem
        .query(
            &prefix,
            &Filter::PrefixOn {
                key: scope_key,
                value: IndexValue::Text("tenant:acme/".into()),
            },
            Page::default(),
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_query_or_empty_matches_nothing_and_all_matches_every_row() {
    // PR #3661 reviewer fix: empty `Or` was returning every row instead
    // of none, and `Filter::All` was being skipped in compound contexts.
    // After the translator change every node emits a non-empty fragment
    // (`All` -> `TRUE`, empty `And` -> `TRUE`, empty `Or` -> `FALSE`).
    let filesystem = libsql_root().await;
    let kind = RecordKind::new("lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    for (path, scope) in [
        ("/secrets/leases/A", "acme"),
        ("/secrets/leases/B", "globex"),
    ] {
        let entry = Entry::record(kind.clone(), &serde_json::json!({}))
            .unwrap()
            .with_indexed(scope_key.clone(), IndexValue::Text(scope.into()));
        filesystem
            .put(
                &VirtualPath::new(path).unwrap(),
                entry,
                CasExpectation::Absent,
            )
            .await
            .unwrap();
    }
    let prefix = VirtualPath::new("/secrets/leases").unwrap();

    // `All` matches every row.
    let all = filesystem
        .query(&prefix, &Filter::All, Page::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 2);

    // Empty `Or` matches nothing.
    let none = filesystem
        .query(&prefix, &Filter::Or(Vec::new()), Page::default())
        .await
        .unwrap();
    assert!(none.is_empty());

    // Empty `And` matches everything (identity).
    let and_empty = filesystem
        .query(&prefix, &Filter::And(Vec::new()), Page::default())
        .await
        .unwrap();
    assert_eq!(and_empty.len(), 2);

    // `And([All])` is well-formed and matches everything.
    let and_all = filesystem
        .query(&prefix, &Filter::And(vec![Filter::All]), Page::default())
        .await
        .unwrap();
    assert_eq!(and_all.len(), 2);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_query_prefix_filter_literal_percent_is_not_a_wildcard() {
    // PR #3661 reviewer fix: a literal prefix containing `%` was being
    // passed to LIKE with its `%` left unescaped (because the prior
    // escape helper preserved trailing `%`). `tenant:%` would then match
    // anything starting with `tenant:` instead of literally `tenant:%`.
    let filesystem = libsql_root().await;
    let kind = RecordKind::new("lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    for (path, scope) in [
        ("/secrets/leases/P1", "tenant:%"),
        ("/secrets/leases/P2", "tenant:acme"),
        ("/secrets/leases/P3", "tenant:globex"),
    ] {
        let entry = Entry::record(kind.clone(), &serde_json::json!({}))
            .unwrap()
            .with_indexed(scope_key.clone(), IndexValue::Text(scope.into()));
        filesystem
            .put(
                &VirtualPath::new(path).unwrap(),
                entry,
                CasExpectation::Absent,
            )
            .await
            .unwrap();
    }

    // Literal-prefix `tenant:%` should match only the row whose stored
    // scope literally starts with `tenant:%`, not the two `tenant:` rows.
    let results = filesystem
        .query(
            &VirtualPath::new("/secrets/leases").unwrap(),
            &Filter::PrefixOn {
                key: scope_key,
                value: IndexValue::Text("tenant:%".into()),
            },
            Page::default(),
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[cfg(feature = "libsql")]
#[tokio::test]
async fn libsql_query_paginates_results() {
    let filesystem = libsql_root().await;
    let kind = RecordKind::new("lease").unwrap();
    let scope_key = IndexKey::new("scope").unwrap();
    let prefix = VirtualPath::new("/secrets/leases").unwrap();

    for i in 0..7 {
        let entry = Entry::record(kind.clone(), &serde_json::json!({"i": i}))
            .unwrap()
            .with_indexed(scope_key.clone(), IndexValue::Text("acme".into()));
        let path = VirtualPath::new(format!("/secrets/leases/page-{i:02}")).unwrap();
        filesystem
            .put(&path, entry, CasExpectation::Absent)
            .await
            .unwrap();
    }

    let first = filesystem
        .query(
            &prefix,
            &Filter::Eq {
                key: scope_key.clone(),
                value: IndexValue::Text("acme".into()),
            },
            Page::new(0, 3),
        )
        .await
        .unwrap();
    assert_eq!(first.len(), 3);

    let second = filesystem
        .query(
            &prefix,
            &Filter::Eq {
                key: scope_key,
                value: IndexValue::Text("acme".into()),
            },
            Page::new(3, 3),
        )
        .await
        .unwrap();
    assert_eq!(second.len(), 3);
    // Pages must not overlap (ordered by path).
    for entry in &second {
        assert!(!first.iter().any(|f| f.entry.body == entry.entry.body));
    }
}

#[cfg(feature = "libsql")]
async fn libsql_root() -> TestLibSqlRootFilesystem {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("root-filesystem.db");
    let db = std::sync::Arc::new(libsql::Builder::new_local(db_path).build().await.unwrap());
    let filesystem = LibSqlRootFilesystem::new(db);
    filesystem.run_migrations().await.unwrap();
    TestLibSqlRootFilesystem {
        filesystem,
        _dir: db_dir,
    }
}
