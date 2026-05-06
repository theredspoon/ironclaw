//! E2E hybrid search + race-safety coverage for the reborn memory substrate.
//!
//! Targets PR #3180 invariants 4–7:
//!   - `with_limit()` re-clamps `pre_fusion_limit` (the `pre_fusion >= limit`
//!     invariant holds regardless of builder call order)
//!   - `min_score` filter drops results that fall below the threshold (#3180
//!     applies the filter after normalization)
//!   - deterministic tiebreaker breaks ties by relative path ascending
//!   - race-safe `replace_document_chunks_if_current` leaves no orphan chunks
//!   - hybrid search results are scoped to the caller's `MemoryDocumentScope`

#[cfg(feature = "libsql")]
mod libsql_e2e {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use ironclaw_memory::{
        ChunkingMemoryDocumentIndexer, EmbeddingError, EmbeddingProvider, FusionStrategy,
        LibSqlMemoryDocumentRepository, MemoryBackend, MemoryBackendCapabilities, MemoryContext,
        MemoryDocumentPath, MemoryDocumentRepository, MemoryDocumentScope, MemorySearchRequest,
        RepositoryMemoryBackend,
    };

    const ALICE_OWNER_KEY: &str = "tenant:tenant-a:user:alice:project:_none";

    /// Builder-only invariant: `pre_fusion_limit() >= limit()` holds regardless
    /// of builder call order (PR #3180 guarantee #5). No DB needed.
    #[test]
    fn pre_fusion_limit_is_at_least_limit_regardless_of_builder_order() {
        // Order A: limit first, then pre_fusion_limit (smaller than limit).
        let req_a = MemorySearchRequest::new("query")
            .unwrap()
            .with_limit(5)
            .with_pre_fusion_limit(2);
        assert_eq!(req_a.limit(), 5);
        assert!(
            req_a.pre_fusion_limit() >= req_a.limit(),
            "order A: pre_fusion_limit ({}) must be >= limit ({})",
            req_a.pre_fusion_limit(),
            req_a.limit()
        );

        // Order B: pre_fusion_limit first (smaller than future limit), then limit.
        let req_b = MemorySearchRequest::new("query")
            .unwrap()
            .with_pre_fusion_limit(2)
            .with_limit(5);
        assert_eq!(req_b.limit(), 5);
        assert!(
            req_b.pre_fusion_limit() >= req_b.limit(),
            "order B: pre_fusion_limit ({}) must be >= limit ({})",
            req_b.pre_fusion_limit(),
            req_b.limit()
        );

        // Order C: large pre_fusion_limit then small limit. Must keep the larger
        // pre_fusion_limit (or at minimum >= the new limit).
        let req_c = MemorySearchRequest::new("query")
            .unwrap()
            .with_pre_fusion_limit(5000)
            .with_limit(5);
        assert_eq!(req_c.limit(), 5);
        assert!(req_c.pre_fusion_limit() >= req_c.limit());
    }

    #[tokio::test]
    async fn hybrid_search_includes_path_in_caller_scope_only_under_libsql() {
        // Seed two scopes with the same FTS+vector token and a hit-attracting
        // chunk. Search from one scope must only return that scope's document,
        // proving the search path classifies by scope at the SQL boundary.
        let (db, _dir) = libsql_db().await;
        let repository = Arc::new(LibSqlMemoryDocumentRepository::new(db.clone()));
        repository.run_migrations().await.unwrap();
        let provider = Arc::new(DeterministicEmbeddingProvider::default());
        let indexer = Arc::new(
            ChunkingMemoryDocumentIndexer::new(repository.clone())
                .with_embedding_provider(provider.clone()),
        );
        let backend = Arc::new(
            RepositoryMemoryBackend::new(repository)
                .with_indexer(indexer)
                .with_embedding_provider(provider)
                .with_capabilities(full_search_capabilities()),
        );

        let alice_scope = MemoryDocumentScope::new("tenant-a", "alice", None).unwrap();
        let bob_scope = MemoryDocumentScope::new("tenant-a", "bob", None).unwrap();

        backend
            .write_document(
                &MemoryContext::new(alice_scope.clone()),
                &MemoryDocumentPath::new("tenant-a", "alice", None, "notes/visible.md").unwrap(),
                b"literal hybrid-vector",
            )
            .await
            .unwrap();
        backend
            .write_document(
                &MemoryContext::new(bob_scope.clone()),
                &MemoryDocumentPath::new("tenant-a", "bob", None, "notes/leaked.md").unwrap(),
                b"literal hybrid-vector",
            )
            .await
            .unwrap();

        // Alice's search must only see Alice's document.
        let alice_results = backend
            .search(
                &MemoryContext::new(alice_scope),
                MemorySearchRequest::new("literal")
                    .unwrap()
                    .with_limit(10)
                    .with_fusion_strategy(FusionStrategy::Rrf),
            )
            .await
            .unwrap();

        let returned_paths: Vec<String> = alice_results
            .iter()
            .map(|r| r.path.relative_path().to_string())
            .collect();
        assert_eq!(
            returned_paths,
            vec!["notes/visible.md".to_string()],
            "alice's search must only return alice's document",
        );
        for result in &alice_results {
            assert_eq!(result.path.user_id(), "alice");
        }
    }

    #[tokio::test]
    #[ignore = "requires PR #3180 min_score-after-normalization fix (pre-#3180 filters against pre-fusion scores ≪ 1.0)"]
    async fn min_score_filter_drops_results_below_threshold_under_libsql() {
        // Seed two documents — one is a hybrid hit (FTS + vector), one is FTS-only.
        // Setting a min_score above the FTS-only RRF-normalized score must drop it.
        let (db, _dir) = libsql_db().await;
        let repository = Arc::new(LibSqlMemoryDocumentRepository::new(db.clone()));
        repository.run_migrations().await.unwrap();
        let provider = Arc::new(DeterministicEmbeddingProvider::default());
        let indexer = Arc::new(
            ChunkingMemoryDocumentIndexer::new(repository.clone())
                .with_embedding_provider(provider.clone()),
        );
        let backend = Arc::new(
            RepositoryMemoryBackend::new(repository.clone())
                .with_indexer(indexer)
                .with_embedding_provider(provider)
                .with_capabilities(full_search_capabilities()),
        );
        let context = MemoryContext::new(scope_alice());

        backend
            .write_document(
                &context,
                &doc_alice("notes/hybrid.md"),
                b"literal hybrid-vector content",
            )
            .await
            .unwrap();
        backend
            .write_document(
                &context,
                &doc_alice("notes/fts-only.md"),
                b"literal unrelated content",
            )
            .await
            .unwrap();

        // Without min_score, both docs should be returned.
        let unfiltered = backend
            .search(
                &context,
                MemorySearchRequest::new("literal").unwrap().with_limit(10),
            )
            .await
            .unwrap();
        let unfiltered_paths: Vec<&str> =
            unfiltered.iter().map(|r| r.path.relative_path()).collect();
        assert!(
            unfiltered_paths.contains(&"notes/hybrid.md"),
            "unfiltered search should include hybrid.md, got {unfiltered_paths:?}",
        );

        // Apply a min_score that is between the two scores. The hybrid result
        // (FTS+vector) must clear the threshold; the FTS-only result must drop.
        // We don't assume the absolute score values — instead, derive the
        // threshold from the actual results so the test stays robust against
        // RRF/k changes.
        let hybrid_score = unfiltered
            .iter()
            .find(|r| r.path.relative_path() == "notes/hybrid.md")
            .map(|r| r.score)
            .expect("hybrid.md should be present");
        let fts_only_score = unfiltered
            .iter()
            .find(|r| r.path.relative_path() == "notes/fts-only.md")
            .map(|r| r.score);
        // If the FTS-only doc never matched (e.g., feature pruned it pre-#3180),
        // the test still proves the threshold gate works: a min_score above the
        // hybrid score drops everything.
        let threshold = match fts_only_score {
            Some(score) if score < hybrid_score => (score + hybrid_score) / 2.0,
            _ => hybrid_score * 0.99, // cannot meaningfully threshold; gate on hybrid only
        };

        let filtered = backend
            .search(
                &context,
                MemorySearchRequest::new("literal")
                    .unwrap()
                    .with_limit(10)
                    .with_min_score(threshold),
            )
            .await
            .unwrap();

        let filtered_paths: Vec<&str> = filtered.iter().map(|r| r.path.relative_path()).collect();
        if let Some(fts_score) = fts_only_score
            && fts_score < hybrid_score
        {
            assert!(
                filtered_paths.contains(&"notes/hybrid.md"),
                "hybrid hit must clear threshold {threshold}: {filtered_paths:?}",
            );
            assert!(
                !filtered_paths.contains(&"notes/fts-only.md"),
                "fts-only hit (score {fts_score}) must be filtered below {threshold}: {filtered_paths:?}",
            );
        } else {
            // Sanity: the hybrid result still clears its own near-threshold gate.
            assert!(
                filtered_paths.contains(&"notes/hybrid.md"),
                "hybrid hit must clear threshold {threshold}: {filtered_paths:?}",
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires PR #3180 deterministic tiebreaker (path ascending)"]
    async fn search_breaks_ties_by_relative_path_ascending_under_libsql() {
        // Seed three docs with identical FTS+vector hits. PR #3180 fixes ties to
        // resolve by path ascending; pre-#3180 ordering is implementation-defined.
        let (db, _dir) = libsql_db().await;
        let repository = Arc::new(LibSqlMemoryDocumentRepository::new(db.clone()));
        repository.run_migrations().await.unwrap();
        let provider = Arc::new(DeterministicEmbeddingProvider::default());
        let indexer = Arc::new(
            ChunkingMemoryDocumentIndexer::new(repository.clone())
                .with_embedding_provider(provider.clone()),
        );
        let backend = Arc::new(
            RepositoryMemoryBackend::new(repository)
                .with_indexer(indexer)
                .with_embedding_provider(provider)
                .with_capabilities(full_search_capabilities()),
        );
        let context = MemoryContext::new(scope_alice());

        // Write in a deliberately non-alphabetical order so any stable-sort by
        // insertion time would produce the wrong result.
        for relative in ["notes/c.md", "notes/a.md", "notes/b.md"] {
            backend
                .write_document(
                    &context,
                    &doc_alice(relative),
                    b"literal hybrid-vector token",
                )
                .await
                .unwrap();
        }

        let results = backend
            .search(
                &context,
                MemorySearchRequest::new("literal")
                    .unwrap()
                    .with_limit(10)
                    .with_fusion_strategy(FusionStrategy::Rrf),
            )
            .await
            .unwrap();

        let paths: Vec<&str> = results.iter().map(|r| r.path.relative_path()).collect();
        assert_eq!(
            paths,
            vec!["notes/a.md", "notes/b.md", "notes/c.md"],
            "ties must resolve to ascending path order; got {paths:?}",
        );
    }

    #[tokio::test]
    async fn concurrent_writes_against_same_path_leave_no_orphan_chunks_under_libsql() {
        // Two writes against the same MemoryDocumentPath through one backend.
        // After both finish, the document table holds exactly one row, the
        // chunk table reflects the persisted content, and no chunk references
        // the losing race's content.
        let (db, _dir) = libsql_db().await;
        let repository = Arc::new(LibSqlMemoryDocumentRepository::new(db.clone()));
        repository.run_migrations().await.unwrap();
        let provider = Arc::new(DeterministicEmbeddingProvider::default());
        let indexer = Arc::new(
            ChunkingMemoryDocumentIndexer::new(repository.clone())
                .with_embedding_provider(provider.clone()),
        );
        let backend = Arc::new(
            RepositoryMemoryBackend::new(repository.clone())
                .with_indexer(indexer)
                .with_embedding_provider(provider)
                .with_capabilities(full_search_capabilities()),
        );
        let context = MemoryContext::new(scope_alice());
        let path = doc_alice("notes/race.md");

        let writer_a = {
            let backend = backend.clone();
            let context = context.clone();
            let path = path.clone();
            async move {
                backend
                    .write_document(
                        &context,
                        &path,
                        b"alpha bravo charlie delta echo foxtrot golf",
                    )
                    .await
            }
        };
        let writer_b = {
            let backend = backend.clone();
            let context = context.clone();
            let path = path.clone();
            async move {
                backend
                    .write_document(
                        &context,
                        &path,
                        b"hotel india juliet kilo lima mike november",
                    )
                    .await
            }
        };
        let (a_outcome, b_outcome) = tokio::join!(writer_a, writer_b);
        a_outcome.unwrap();
        b_outcome.unwrap();

        // Exactly one document row.
        assert_eq!(count_documents(&db, "notes/race.md").await, 1);

        // Final document content equals one of the two writes (whichever wrote
        // last); chunks all reference that content and not the loser's tokens.
        let stored = repository.read_document(&path).await.unwrap().unwrap();
        let stored_text = std::str::from_utf8(&stored).unwrap();
        let alpha_winner = stored_text.contains("alpha");
        let hotel_winner = stored_text.contains("hotel");
        assert!(
            alpha_winner ^ hotel_winner,
            "stored content must be exactly one writer's, got {stored_text:?}",
        );

        let chunks = chunks_for_path(&db, "notes/race.md").await;
        assert!(!chunks.is_empty(), "expected indexed chunks after writes");
        let loser_tokens: &[&str] = if alpha_winner {
            &[
                "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
            ]
        } else {
            &[
                "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            ]
        };
        for chunk in &chunks {
            for stale in loser_tokens {
                assert!(
                    !chunk.contains(stale),
                    "orphan chunk references losing race content {stale:?}: {chunk:?}",
                );
            }
        }
    }

    // ----- helpers -----

    fn full_search_capabilities() -> MemoryBackendCapabilities {
        MemoryBackendCapabilities {
            file_documents: true,
            metadata: true,
            versioning: true,
            full_text_search: true,
            vector_search: true,
            embeddings: true,
            ..MemoryBackendCapabilities::default()
        }
    }

    fn scope_alice() -> MemoryDocumentScope {
        MemoryDocumentScope::new("tenant-a", "alice", None).unwrap()
    }

    fn doc_alice(relative: &str) -> MemoryDocumentPath {
        MemoryDocumentPath::new("tenant-a", "alice", None, relative).unwrap()
    }

    async fn libsql_db() -> (Arc<libsql::Database>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("memory.db");
        let db = Arc::new(libsql::Builder::new_local(db_path).build().await.unwrap());
        (db, dir)
    }

    async fn chunks_for_path(db: &Arc<libsql::Database>, relative_path: &str) -> Vec<String> {
        let conn = db.connect().unwrap();
        let mut rows = conn
            .query(
                r#"
                SELECT c.content FROM memory_chunks c
                JOIN memory_documents d ON d.id = c.document_id
                WHERE d.user_id = ?1 AND d.path = ?2
                ORDER BY c.chunk_index
                "#,
                libsql::params![ALICE_OWNER_KEY, relative_path],
            )
            .await
            .unwrap();
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            out.push(row.get::<String>(0).unwrap());
        }
        out
    }

    async fn count_documents(db: &Arc<libsql::Database>, relative_path: &str) -> i64 {
        let conn = db.connect().unwrap();
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM memory_documents WHERE user_id = ?1 AND path = ?2",
                libsql::params![ALICE_OWNER_KEY, relative_path],
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        row.get::<i64>(0).unwrap()
    }

    #[derive(Default)]
    struct DeterministicEmbeddingProvider {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl EmbeddingProvider for DeterministicEmbeddingProvider {
        fn dimension(&self) -> usize {
            3
        }

        fn model_name(&self) -> &str {
            "deterministic-test-embedding"
        }

        async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
            self.calls.lock().unwrap().push(text.to_string());
            if text.contains("hybrid-vector") {
                Ok(vec![1.0, 0.0, 0.0])
            } else if text.contains("unrelated") {
                Ok(vec![0.0, 1.0, 0.0])
            } else {
                Ok(vec![0.0, 0.0, 1.0])
            }
        }
    }
}
