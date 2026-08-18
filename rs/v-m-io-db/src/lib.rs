#![deny(missing_docs)]
//! v-m.io all service runtime database

use sha2::Digest;
use std::io::Result;
use std::sync::Arc;

mod blob;
mod key;
mod sql;

/// Database entry.
pub struct VmIoDbEntry {
    /// entry class identifier
    pub class: String,

    /// entry key identifier
    pub key: String,

    /// entry created at unix epoch timestamp in microseconds
    pub modified_at_micros: i64,

    /// if specified, entry will be pruned after this unix epoch timestamp in
    /// microseconds
    ///
    /// Pruning is periodic, so an entry remains readable for up to a minute
    /// past this timestamp.
    pub expires_at_micros: Option<i64>,

    /// optional metadata associated with entry
    pub metadata: Option<Vec<u8>>,

    /// chunk count for file data (0 for no file)
    pub chunk_count: i64,
}

/// Specify how the list should be filtered.
pub enum VmIoDbListFilter {
    /// Do not filter, get all items.
    All,

    /// Filter by key prefix.
    KeyPrefix(String),

    /// Filter by modified_at_micros range.
    ModifiedAtMicrosRange {
        /// start of filter range.
        start: std::ops::Bound<i64>,

        /// end of filter range.
        end: std::ops::Bound<i64>,
    },
}

/// Specify how the list should be sorted.
pub enum VmIoDbListSort {
    /// default sorting by key ascending
    KeyAsc,

    /// default sorting by key descending
    KeyDesc,

    /// by modified_at_micros ascending
    ModifiedAtMicrosAsc,

    /// by modified_at_micros descending
    ModifiedAtMicrosDesc,
}

/// v-m.io all service runtime database
pub struct VmIoDb {
    root_dir: std::path::PathBuf,
    sql: Arc<sql::Sql>,

    // the blob sub key, not the caller's master key
    blob_key: zeroize::Zeroizing<[u8; 32]>,

    // dropping the set aborts the background tasks with the database
    _tasks: tokio::task::JoinSet<()>,
}

/// How long to wait between expiration prune passes.
const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum count of entries pruned in a single transaction.
///
/// Pruning holds the exclusive write transaction, so a large backlog of
/// expirations is worked through in batches rather than stalling writers
/// behind one long delete.
const PRUNE_BATCH: i64 = 256;

/// Drain the backlog of entries that have already expired, a batch at a
/// time, so a large number of simultaneous expirations does not take
/// PRUNE_INTERVAL per batch to clear.
///
/// Split out of [prune_task] so tests can drive a pass on demand instead of
/// waiting on its sleep loop.
async fn prune_backlog(
    root_dir: &std::path::Path,
    sql: &sql::Sql,
) -> Result<()> {
    while let Ok(now_micros) = unix_micros() {
        let (count, blob_ids) =
            sql.prune_expired(now_micros, PRUNE_BATCH).await?;

        for blob_id in blob_ids {
            // best effort - these are unreferenced now, so anything we fail
            // to remove here is collected by the cleanup task
            let _ =
                tokio::fs::remove_file(blob::id_path(root_dir, &blob_id)).await;
        }

        if count < PRUNE_BATCH as usize {
            break;
        }
    }

    Ok(())
}

/// Periodically remove entries that have passed their expiration.
async fn prune_task(root_dir: std::path::PathBuf, sql: Arc<sql::Sql>) {
    loop {
        // best effort - errors are retried on the next pass
        let _ = prune_backlog(&root_dir, &sql).await;

        tokio::time::sleep(PRUNE_INTERVAL).await;
    }
}

/// Current unix epoch timestamp in microseconds.
fn unix_micros() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|since| since.as_micros() as i64)
        .map_err(std::io::Error::other)
}

/// How long to wait between disk cleanup passes.
const CLEANUP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60 * 10);

/// Blob files and shard directories are only removed once they have gone
/// untouched for at least this long.
///
/// [VmIoDb::upsert_chunk] writes the blob file *before* committing the sql
/// row that references it, so a recently written file with no sql reference
/// may well be a write in flight rather than garbage. The grace period just
/// has to comfortably exceed the gap between those two steps.
const CLEANUP_GRACE: std::time::Duration =
    std::time::Duration::from_secs(60 * 5);

/// Periodically reclaim disk that sql no longer references.
async fn cleanup_task(root_dir: std::path::PathBuf, sql: Arc<sql::Sql>) {
    loop {
        if let Some(cutoff) =
            std::time::SystemTime::now().checked_sub(CLEANUP_GRACE)
        {
            // best effort - io and sql errors abort this pass, and whatever
            // was missed is picked up by the next one
            let _ =
                cleanup_dir(&root_dir, &sql, root_dir.clone(), 0, cutoff).await;
        }

        tokio::time::sleep(CLEANUP_INTERVAL).await;
    }
}

/// Recursive worker for [cleanup_task]. Descends the blob shard tree,
/// removing unreferenced blob files, then the shard directories they leave
/// empty behind them.
fn cleanup_dir<'a>(
    root_dir: &'a std::path::Path,
    sql: &'a sql::Sql,
    dir: std::path::PathBuf,
    depth: usize,
    cutoff: std::time::SystemTime,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
{
    Box::pin(async move {
        let mut read_dir = tokio::fs::read_dir(&dir).await?;

        while let Some(item) = read_dir.next_entry().await? {
            let name = item.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };

            let Ok(meta) = item.metadata().await else {
                // vanished out from under us, or otherwise unreadable
                continue;
            };

            let stale = meta
                .modified()
                .map(|modified| modified <= cutoff)
                .unwrap_or(false);

            if meta.is_dir() {
                // only walk our own layout, never anything else that
                // happens to live in the root dir (the sqlite files)
                if depth >= blob::SHARD_DEPTH || !blob::is_shard_name(name) {
                    continue;
                }

                cleanup_dir(root_dir, sql, item.path(), depth + 1, cutoff)
                    .await?;

                if stale {
                    // only succeeds if the recursion above left it empty.
                    // note that removing children bumps this dir's mtime,
                    // so its own parent becomes collectable on a later pass
                    let _ = tokio::fs::remove_dir(item.path()).await;
                }
            } else if depth == blob::SHARD_DEPTH && stale {
                // a blob file is only reachable through the chunk row whose
                // blob id names it, so no row means no reference
                let Some(id) = blob::parse_name(name) else {
                    continue;
                };

                if blob::id_path(root_dir, &id) != item.path() {
                    // correctly named but not where we would have put it
                    continue;
                }

                if !sql.blob_id_exists(id).await? {
                    let _ = tokio::fs::remove_file(item.path()).await;
                }
            }
        }

        Ok(())
    })
}

impl VmIoDb {
    /// Construct a new database.
    ///
    /// `encryption_key` is a master key. It is split into independent sub keys
    /// for the database and for entry file blobs, and is not itself retained.
    pub async fn new<P: Into<std::path::PathBuf>>(
        root_dir: P,
        encryption_key: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let root_dir = root_dir.into();
        tokio::fs::create_dir_all(&root_dir).await?;

        let mut sql_path = root_dir.clone();
        sql_path.push("db.sqlite");

        let keys = key::RootKeys::derive(&encryption_key);
        drop(encryption_key);

        let sql = Arc::new(sql::Sql::new(sql_path, keys.sqlite).await?);

        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(prune_task(root_dir.clone(), sql.clone()));
        tasks.spawn(cleanup_task(root_dir.clone(), sql.clone()));

        Ok(Self {
            root_dir,
            sql,
            blob_key: keys.blob,
            _tasks: tasks,
        })
    }

    /// Upsert an entry.
    pub async fn upsert(
        &self,
        class: String,
        key: String,
        modified_at_micros: i64,
        expires_at_micros: Option<i64>,
        metadata: Option<Vec<u8>>,
    ) -> Result<()> {
        if class.len() > 256 {
            return Err(std::io::Error::other("class cannot be > 256 bytes"));
        }

        if key.len() > 1024 {
            return Err(std::io::Error::other("key cannot be > 1024 bytes"));
        }

        if let Some(metadata) = metadata.as_ref()
            && metadata.len() > 4096
        {
            return Err(std::io::Error::other(
                "metadata cannot be > 4096 bytes",
            ));
        }

        self.sql
            .upsert(class, key, modified_at_micros, expires_at_micros, metadata)
            .await
    }

    /// Upsert a chunk.
    pub async fn upsert_chunk(
        &self,
        class: String,
        key: String,
        idx: i64,
        mut data: Vec<u8>,
        is_final: bool,
    ) -> Result<()> {
        if !is_final && data.len() != 1024 * 1024 * 5 {
            return Err(std::io::Error::other(
                "non-final chunks must be 5 MiB",
            ));
        } else if is_final && data.len() > 1024 * 1024 * 5 {
            return Err(std::io::Error::other(
                "final chunks cannot be > 5 MiB",
            ));
        }

        let hash: [u8; 32] = sha2::Sha256::digest(&data).into();

        let blob::EncryptResult { id: blob_id, tag } = blob::encrypt_chunk(
            &blob::ChunkId {
                class: &class,
                key: &key,
                idx,
                hash: &hash,
                is_final,
            },
            &mut data[..],
            &self.blob_key,
        );

        let path = blob::id_path(&self.root_dir, &blob_id);

        // a blob's contents are a pure function of the path it lives at, so a
        // file already there at full length is byte for byte what we would
        // write. skipping the write keeps blobs write once: it cannot truncate
        // a file that a committed row still depends on, which is what made
        // rewriting the same chunk risky when nonces were random
        let wrote = match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() == data.len() as u64 => false,
            _ => {
                blob::write(&path, &data).await?;
                true
            }
        };

        match self
            .sql
            .upsert_chunk(
                class,
                key,
                idx,
                blob_id,
                hash,
                tag,
                data.len() as i64,
                is_final,
            )
            .await
        {
            Err(err) => {
                // only ours to remove if this call is what put it there
                if wrote {
                    let _ = tokio::fs::remove_file(&path).await;
                }
                Err(err)
            }
            Ok(prev) => {
                if let Some(prev) = prev {
                    // this chunk index used to point at a different blob,
                    // which is now unreferenced. best effort - the cleanup
                    // task collects it if this fails
                    let _ = tokio::fs::remove_file(blob::id_path(
                        &self.root_dir,
                        &prev,
                    ))
                    .await;
                }
                Ok(())
            }
        }
    }

    /// Remove an entry.
    pub async fn rm(&self, class: String, key: String) -> Result<()> {
        for blob_id in self.sql.rm(class, key).await? {
            // best effort - the sql rows are already gone, so anything we
            // fail to remove here is unreferenced and the cleanup task
            // collects it
            let _ =
                tokio::fs::remove_file(blob::id_path(&self.root_dir, &blob_id))
                    .await;
        }
        Ok(())
    }

    /// Get an entry.
    pub async fn get(
        &self,
        class: String,
        key: String,
    ) -> Result<Option<VmIoDbEntry>> {
        self.sql.get(class, key).await
    }

    /// Get an entry file chunk.
    pub async fn get_chunk(
        &self,
        class: String,
        key: String,
        idx: i64,
        is_final: bool,
    ) -> Result<Option<Vec<u8>>> {
        let chunk =
            match self.sql.get_chunk(class.clone(), key.clone(), idx).await? {
                None => return Ok(None),
                Some(chunk) => chunk,
            };

        if is_final != chunk.is_final {
            return Err(std::io::Error::other("chunk finality mismatch"));
        }

        let chunk_id = blob::ChunkId {
            class: &class,
            key: &key,
            idx,
            hash: &chunk.hash,
            is_final,
        };

        let path = blob::id_path(
            &self.root_dir,
            &blob::gen_id(&chunk_id, &self.blob_key),
        );
        let mut data = tokio::fs::read(path).await?;

        if data.len() != chunk.size as usize {
            return Err(std::io::Error::other("corrupted chunk"));
        }

        blob::decrypt_chunk(
            &chunk_id,
            &mut data[..],
            &self.blob_key,
            &chunk.tag,
        )?;

        Ok(Some(data))
    }

    /// List entries.
    pub async fn list(
        &self,
        class: String,
        filter: VmIoDbListFilter,
        sort: VmIoDbListSort,
        limit: i64,
    ) -> Result<Vec<VmIoDbEntry>> {
        self.sql.list(class, filter, sort, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_db() -> Result<(VmIoDb, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let db = VmIoDb::new(dir.path(), [0xdb; 32].into()).await?;
        Ok((db, dir))
    }

    #[tokio::test]
    async fn sanity() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 42, None, None)
            .await
            .unwrap();

        let e = db.get("c".into(), "k".into()).await.unwrap().unwrap();
        assert_eq!(42, e.modified_at_micros);
        assert_eq!(0, e.chunk_count);

        db.upsert_chunk("c".into(), "k".into(), 0, b"hello".into(), true)
            .await
            .unwrap();

        let e = db.get("c".into(), "k".into()).await.unwrap().unwrap();
        assert_eq!(1, e.chunk_count);

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(1, l.len());
        assert_eq!(1, l[0].chunk_count);

        let c = db
            .get_chunk("c".into(), "k".into(), 0, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!("hello", String::from_utf8_lossy(&c));

        db.rm("c".into(), "k".into()).await.unwrap();
    }

    #[tokio::test]
    async fn list_all_is_class_scoped_and_sortable() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "b".into(), 20, None, None)
            .await
            .unwrap();
        db.upsert("c".into(), "a".into(), 10, None, None)
            .await
            .unwrap();
        db.upsert("c".into(), "c".into(), 30, None, None)
            .await
            .unwrap();
        // different class entirely - must never show up in "c" listings
        db.upsert("other".into(), "z".into(), 40, None, None)
            .await
            .unwrap();

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["a", "b", "c"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::KeyDesc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["c", "b", "a"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::ModifiedAtMicrosAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["a", "b", "c"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::ModifiedAtMicrosDesc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["c", "b", "a"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_respects_limit() {
        let (db, _dir) = make_db().await.unwrap();

        for (i, k) in ["a", "b", "c"].into_iter().enumerate() {
            db.upsert("c".into(), k.into(), i as i64, None, None)
                .await
                .unwrap();
        }

        let l = db
            .list("c".into(), VmIoDbListFilter::All, VmIoDbListSort::KeyAsc, 2)
            .await
            .unwrap();
        assert_eq!(
            vec!["a", "b"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_key_prefix_matches_only_that_prefix() {
        let (db, _dir) = make_db().await.unwrap();

        for (i, k) in ["dog/1", "dog/2", "cat/1"].into_iter().enumerate() {
            db.upsert("c".into(), k.into(), i as i64, None, None)
                .await
                .unwrap();
        }

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::KeyPrefix("dog/".into()),
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["dog/1", "dog/2"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_key_prefix_escapes_glob_metacharacters() {
        let (db, _dir) = make_db().await.unwrap();

        // a naive, unescaped GLOB would treat these prefixes' metacharacters
        // as wildcards and match far more than the intended literal prefix
        for (i, k) in ["a*1", "a*2", "aXY", "abc", "b?1", "bZ1", "c[x", "cYx"]
            .into_iter()
            .enumerate()
        {
            db.upsert("c".into(), k.into(), i as i64, None, None)
                .await
                .unwrap();
        }

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::KeyPrefix("a*".into()),
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["a*1", "a*2"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::KeyPrefix("b?".into()),
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["b?1"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::KeyPrefix("c[".into()),
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["c[x"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_modified_at_micros_range() {
        let (db, _dir) = make_db().await.unwrap();

        for (k, t) in [("a", 10), ("b", 20), ("c", 30), ("d", 40)] {
            db.upsert("c".into(), k.into(), t, None, None)
                .await
                .unwrap();
        }

        // inclusive/inclusive
        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::ModifiedAtMicrosRange {
                    start: std::ops::Bound::Included(20),
                    end: std::ops::Bound::Included(30),
                },
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["b", "c"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        // exclusive/exclusive narrows both ends by one
        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::ModifiedAtMicrosRange {
                    start: std::ops::Bound::Excluded(10),
                    end: std::ops::Bound::Excluded(40),
                },
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["b", "c"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        // unbounded start, bounded end
        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::ModifiedAtMicrosRange {
                    start: std::ops::Bound::Unbounded,
                    end: std::ops::Bound::Included(20),
                },
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["a", "b"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );

        // bounded start, unbounded end
        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::ModifiedAtMicrosRange {
                    start: std::ops::Bound::Included(30),
                    end: std::ops::Bound::Unbounded,
                },
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["c", "d"],
            l.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn upsert_validates_field_lengths() {
        let (db, _dir) = make_db().await.unwrap();

        assert!(
            db.upsert("c".repeat(257), "k".into(), 1, None, None)
                .await
                .is_err()
        );
        assert!(
            db.upsert("c".into(), "k".repeat(1025), 1, None, None)
                .await
                .is_err()
        );
        assert!(
            db.upsert("c".into(), "k".into(), 1, None, Some(vec![0; 4097]),)
                .await
                .is_err()
        );

        // nothing should have been written by the failed calls above
        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert!(l.is_empty());
    }

    #[tokio::test]
    async fn upsert_chunk_validates_size() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();

        // non-final chunks must be exactly 5 MiB
        assert!(
            db.upsert_chunk("c".into(), "k".into(), 0, vec![0; 10], false)
                .await
                .is_err()
        );

        // final chunks may not exceed 5 MiB
        assert!(
            db.upsert_chunk(
                "c".into(),
                "k".into(),
                0,
                vec![0; 1024 * 1024 * 5 + 1],
                true,
            )
            .await
            .is_err()
        );

        // exactly 5 MiB is allowed for a final chunk
        db.upsert_chunk(
            "c".into(),
            "k".into(),
            0,
            vec![0; 1024 * 1024 * 5],
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_entry() {
        let (db, _dir) = make_db().await.unwrap();

        assert!(
            db.get("c".into(), "missing".into())
                .await
                .unwrap()
                .is_none()
        );

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();
        assert!(db.get("other".into(), "k".into()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_chunk_returns_none_for_missing_chunk() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();

        assert!(
            db.get_chunk("c".into(), "k".into(), 0, true)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_chunk_errors_on_finality_mismatch() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "k".into(), 0, b"hello".to_vec(), true)
            .await
            .unwrap();

        assert!(
            db.get_chunk("c".into(), "k".into(), 0, false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn multi_chunk_file_round_trips() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();

        let first = vec![7u8; 1024 * 1024 * 5];
        db.upsert_chunk("c".into(), "k".into(), 0, first.clone(), false)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "k".into(), 1, b"tail".to_vec(), true)
            .await
            .unwrap();

        let e = db.get("c".into(), "k".into()).await.unwrap().unwrap();
        assert_eq!(2, e.chunk_count);

        let c0 = db
            .get_chunk("c".into(), "k".into(), 0, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, c0);

        let c1 = db
            .get_chunk("c".into(), "k".into(), 1, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b"tail", c1.as_slice());
    }

    /// Path of the blob file backing a given (final) chunk, computed the same
    /// way [VmIoDb::upsert_chunk] does, so tests can assert on disk state
    /// without the db exposing blob ids as part of its public api.
    fn chunk_blob_path(
        db: &VmIoDb,
        class: &str,
        key: &str,
        idx: i64,
        data: &[u8],
        is_final: bool,
    ) -> std::path::PathBuf {
        let hash: [u8; 32] = sha2::Sha256::digest(data).into();
        let id = blob::gen_id(
            &blob::ChunkId {
                class,
                key,
                idx,
                hash: &hash,
                is_final,
            },
            &db.blob_key,
        );
        blob::id_path(&db.root_dir, &id)
    }

    #[tokio::test]
    async fn rm_deletes_entry_and_blob_files() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "k".into(), 0, b"hello".to_vec(), true)
            .await
            .unwrap();

        let path = chunk_blob_path(&db, "c", "k", 0, b"hello", true);
        assert!(tokio::fs::metadata(&path).await.is_ok());

        db.rm("c".into(), "k".into()).await.unwrap();

        assert!(db.get("c".into(), "k".into()).await.unwrap().is_none());
        assert!(tokio::fs::metadata(&path).await.is_err());
    }

    #[tokio::test]
    async fn upsert_chunk_replaces_blob_on_content_change() {
        let (db, _dir) = make_db().await.unwrap();

        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "k".into(), 0, b"hello".to_vec(), true)
            .await
            .unwrap();
        let old_path = chunk_blob_path(&db, "c", "k", 0, b"hello", true);
        assert!(tokio::fs::metadata(&old_path).await.is_ok());

        // rewriting identical content is a no-op: same blob path, still
        // there, and the call itself must not fail
        db.upsert_chunk("c".into(), "k".into(), 0, b"hello".to_vec(), true)
            .await
            .unwrap();
        assert!(tokio::fs::metadata(&old_path).await.is_ok());

        // rewriting with different content moves the chunk to a new blob
        // and cleans up the one it no longer references
        db.upsert_chunk("c".into(), "k".into(), 0, b"world!".to_vec(), true)
            .await
            .unwrap();
        let new_path = chunk_blob_path(&db, "c", "k", 0, b"world!", true);
        assert_ne!(old_path, new_path);
        assert!(tokio::fs::metadata(&old_path).await.is_err());
        assert!(tokio::fs::metadata(&new_path).await.is_ok());

        let c = db
            .get_chunk("c".into(), "k".into(), 0, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b"world!", c.as_slice());
    }

    #[tokio::test]
    async fn prune_backlog_removes_only_expired_entries() {
        let (db, _dir) = make_db().await.unwrap();
        let now = unix_micros().unwrap();

        // insert not-yet-expired, so the real prune_task spawned alongside
        // this db (which the test never controls the timing of) cannot race
        // the entry out from under upsert_chunk's foreign key before the
        // chunk is attached
        db.upsert("c".into(), "expired".into(), 1, None, None)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "expired".into(), 0, b"old".to_vec(), true)
            .await
            .unwrap();
        let blob_path = chunk_blob_path(&db, "c", "expired", 0, b"old", true);
        assert!(tokio::fs::metadata(&blob_path).await.is_ok());

        // now mark it expired
        db.upsert("c".into(), "expired".into(), 4, Some(now - 1_000_000), None)
            .await
            .unwrap();

        db.upsert(
            "c".into(),
            "future".into(),
            2,
            Some(now + 1_000_000_000),
            None,
        )
        .await
        .unwrap();
        db.upsert("c".into(), "forever".into(), 3, None, None)
            .await
            .unwrap();

        prune_backlog(&db.root_dir, &db.sql).await.unwrap();

        assert!(
            db.get("c".into(), "expired".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.get("c".into(), "future".into()).await.unwrap().is_some());
        assert!(
            db.get("c".into(), "forever".into())
                .await
                .unwrap()
                .is_some()
        );

        // prune_backlog removes the blob file directly; the now-empty shard
        // directories it leaves behind are the disk cleanup task's job
        assert!(tokio::fs::metadata(&blob_path).await.is_err());
    }

    #[tokio::test]
    async fn prune_backlog_drains_a_backlog_larger_than_one_batch() {
        let (db, _dir) = make_db().await.unwrap();
        let now = unix_micros().unwrap();

        let total = PRUNE_BATCH as usize + 44;
        for i in 0..total {
            db.upsert(
                "c".into(),
                format!("k{i}"),
                i as i64 + 1,
                Some(now - 1_000_000),
                None,
            )
            .await
            .unwrap();
        }

        // a single call must fully drain the backlog, not just one batch
        prune_backlog(&db.root_dir, &db.sql).await.unwrap();

        let l = db
            .list(
                "c".into(),
                VmIoDbListFilter::All,
                VmIoDbListSort::KeyAsc,
                i64::MAX,
            )
            .await
            .unwrap();
        assert!(l.is_empty());
    }

    #[tokio::test]
    async fn cleanup_dir_removes_stale_unreferenced_blobs_and_empty_shards() {
        let (db, _dir) = make_db().await.unwrap();

        // a real, referenced chunk - must survive cleanup no matter how
        // stale it looks, since a sql row still references it
        db.upsert("c".into(), "k".into(), 1, None, None)
            .await
            .unwrap();
        db.upsert_chunk("c".into(), "k".into(), 0, b"kept".to_vec(), true)
            .await
            .unwrap();
        let kept_path = chunk_blob_path(&db, "c", "k", 0, b"kept", true);

        // an orphan blob with no sql row referencing it, as if a crash had
        // interrupted upsert_chunk after the file write but before commit
        let orphan_path = blob::id_path(&db.root_dir, &[0xAA; 32]);
        blob::write(&orphan_path, b"orphan").await.unwrap();

        assert!(tokio::fs::metadata(&kept_path).await.is_ok());
        assert!(tokio::fs::metadata(&orphan_path).await.is_ok());

        // a cutoff in the future makes everything just written look past
        // its grace period, without having to sleep out CLEANUP_GRACE
        let cutoff =
            std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        cleanup_dir(&db.root_dir, &db.sql, db.root_dir.clone(), 0, cutoff)
            .await
            .unwrap();

        assert!(tokio::fs::metadata(&kept_path).await.is_ok());
        assert!(tokio::fs::metadata(&orphan_path).await.is_err());

        // the shard directories that only ever held the orphan should have
        // been pruned along with it once they were left empty
        assert!(
            tokio::fs::metadata(orphan_path.parent().unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cleanup_dir_respects_grace_period_for_fresh_orphans() {
        let (db, _dir) = make_db().await.unwrap();

        let orphan_path = blob::id_path(&db.root_dir, &[0xBB; 32]);
        blob::write(&orphan_path, b"orphan").await.unwrap();

        // a cutoff well in the past means nothing just written qualifies as
        // stale yet, mirroring a real pass that runs before CLEANUP_GRACE
        // has elapsed
        let cutoff =
            std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        cleanup_dir(&db.root_dir, &db.sql, db.root_dir.clone(), 0, cutoff)
            .await
            .unwrap();

        assert!(tokio::fs::metadata(&orphan_path).await.is_ok());
    }
}
