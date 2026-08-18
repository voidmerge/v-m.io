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

/// Periodically remove entries that have passed their expiration.
async fn prune_task(root_dir: std::path::PathBuf, sql: Arc<sql::Sql>) {
    loop {
        // drain the backlog a batch at a time before waiting for the next
        // pass, so a large number of simultaneous expirations does not take
        // PRUNE_INTERVAL per batch to clear
        while let Ok(now_micros) = unix_micros() {
            let (count, blob_ids) =
                match sql.prune_expired(now_micros, PRUNE_BATCH).await {
                    // best effort - retry on the next pass
                    Err(_) => break,
                    Ok(pruned) => pruned,
                };

            for blob_id in blob_ids {
                // best effort - these are unreferenced now, so anything we
                // fail to remove here is collected by the cleanup task
                let _ =
                    tokio::fs::remove_file(blob::id_path(&root_dir, &blob_id))
                        .await;
            }

            if count < PRUNE_BATCH as usize {
                break;
            }
        }

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
}
