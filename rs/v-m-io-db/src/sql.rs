use std::io::Result;
use std::sync::{Arc, Mutex};

const PRAGMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
";

const SCHEMA: &str = include_str!("sql/schema.sql");
const UPSERT: &str = include_str!("sql/upsert.sql");
const UPSERT_CHUNK: &str = include_str!("sql/upsert_chunk.sql");
const GET_ENTRY: &str = include_str!("sql/get_entry.sql");
const GET_CHUNK: &str = include_str!("sql/get_chunk.sql");
const GET_CHUNK_BLOB_ID: &str = include_str!("sql/get_chunk_blob_id.sql");
const BLOB_ID_EXISTS: &str = include_str!("sql/blob_id_exists.sql");
const PRUNE_EXPIRED: &str = include_str!("sql/prune_expired.sql");
const PRUNE_EXPIRED_BLOB_IDS: &str =
    include_str!("sql/prune_expired_blob_ids.sql");

/// Render a key as the `x'<hex>'` literal that selects sqlcipher's raw key
/// mode, which uses the given bytes directly instead of running them through
/// a passphrase kdf.
pub fn key_literal(
    secret: &zeroize::Zeroizing<[u8; 32]>,
) -> zeroize::Zeroizing<[u8; 67]> {
    let mut hex_buffer = [0u8; 67];
    hex_buffer[0] = b'x';
    hex_buffer[1] = b'\'';
    hex_buffer[66] = b'\'';

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    for (i, &byte) in secret.as_ref().iter().enumerate() {
        hex_buffer[i * 2 + 2] = HEX_CHARS[(byte >> 4) as usize];
        hex_buffer[i * 2 + 3] = HEX_CHARS[(byte & 0x0f) as usize];
    }

    zeroize::Zeroizing::new(hex_buffer)
}

/// Build a sqlite `GLOB` pattern that matches keys starting with `prefix`.
///
/// `GLOB` has no `ESCAPE` clause (unlike `LIKE`), so any of its wildcard
/// characters (`*`, `?`, `[`) occurring in `prefix` are neutralized by
/// wrapping them in a single-char character class, e.g. `*` becomes `[*]`.
fn glob_prefix_pattern(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for c in prefix.chars() {
        match c {
            '*' | '?' | '[' => {
                pattern.push('[');
                pattern.push(c);
                pattern.push(']');
            }
            _ => pattern.push(c),
        }
    }
    pattern.push('*');
    pattern
}

/// sqlite db connection
pub struct Sql {
    c_write: Arc<Mutex<rusqlite::Connection>>,
    c_read_pool: Arc<RingPool<rusqlite::Connection>>,
}

impl Sql {
    /// Construct a new db connection pool.
    pub async fn new<P: Into<std::path::PathBuf>>(
        path: P,
        sqlite_key: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let path = path.into();
        tokio::task::spawn_blocking(move || {
            let c_write = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(std::io::Error::other)?;

            let hex_key = key_literal(&sqlite_key);
            let hex_key = std::str::from_utf8(&hex_key[..]).unwrap();

            c_write
                .pragma_update(None, "key", hex_key)
                .map_err(std::io::Error::other)?;
            c_write
                .execute_batch(PRAGMA)
                .map_err(std::io::Error::other)?;
            c_write
                .execute_batch(SCHEMA)
                .map_err(std::io::Error::other)?;

            let c_read_1 = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(std::io::Error::other)?;

            c_read_1
                .pragma_update(None, "key", hex_key)
                .map_err(std::io::Error::other)?;
            c_read_1
                .execute_batch(PRAGMA)
                .map_err(std::io::Error::other)?;

            let c_read_2 = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(std::io::Error::other)?;

            c_read_2
                .pragma_update(None, "key", hex_key)
                .map_err(std::io::Error::other)?;
            c_read_2
                .execute_batch(PRAGMA)
                .map_err(std::io::Error::other)?;

            let c_read_3 = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(std::io::Error::other)?;

            c_read_3
                .pragma_update(None, "key", hex_key)
                .map_err(std::io::Error::other)?;
            c_read_3
                .execute_batch(PRAGMA)
                .map_err(std::io::Error::other)?;

            Ok(Self {
                c_write: Arc::new(Mutex::new(c_write)),
                c_read_pool: Arc::new(RingPool::new(
                    c_read_1, c_read_2, c_read_3,
                )),
            })
        })
        .await
        .expect("blocking thread error")
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
        let c_write = self.c_write.clone();
        tokio::task::spawn_blocking(move || {
            c_write
                .lock()
                .unwrap()
                .execute(
                    UPSERT,
                    rusqlite::params![
                        class,
                        key,
                        modified_at_micros,
                        expires_at_micros,
                        metadata,
                    ],
                )
                .map_err(std::io::Error::other)?;
            Ok(())
        })
        .await
        .expect("blocking thread error")
    }

    /// Upsert a chunk.
    ///
    /// If this replaced a chunk backed by a different blob file, the id of
    /// that now unreferenced blob is returned so it can be removed.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_chunk(
        &self,
        class: String,
        key: String,
        idx: i64,
        blob_id: [u8; 32],
        hash: [u8; 32],
        tag: [u8; 32],
        size: i64,
        is_final: bool,
    ) -> Result<Option<[u8; 32]>> {
        let c_write = self.c_write.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_write = c_write.lock().unwrap();
            let tx = c_write
                .transaction_with_behavior(
                    rusqlite::TransactionBehavior::Exclusive,
                )
                .map_err(std::io::Error::other)?;

            let prev: Option<[u8; 32]> = match tx.query_one(
                GET_CHUNK_BLOB_ID,
                rusqlite::params![&class, &key, idx],
                |row| row.get(0),
            ) {
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(err) => return Err(std::io::Error::other(err)),
                Ok(prev) => Some(prev),
            };

            tx.execute(
                UPSERT_CHUNK,
                rusqlite::params![
                    class, key, idx, blob_id, hash, tag, size, is_final,
                ],
            )
            .map_err(std::io::Error::other)?;

            tx.commit().map_err(std::io::Error::other)?;

            // a rewrite of identical content lands on the same blob file,
            // in which case there is nothing to clean up
            Ok(prev.filter(|prev| prev != &blob_id))
        })
        .await
        .expect("blocking thread error")
    }

    /// Is any chunk still referencing this blob id?
    pub async fn blob_id_exists(&self, blob_id: [u8; 32]) -> Result<bool> {
        let c_read_pool = self.c_read_pool.clone();
        tokio::task::spawn_blocking(move || {
            let c_read = c_read_pool.get();
            match c_read.query_one(
                BLOB_ID_EXISTS,
                rusqlite::params![blob_id],
                |_row| Ok(()),
            ) {
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
                Err(err) => Err(std::io::Error::other(err)),
                Ok(_) => Ok(true),
            }
        })
        .await
        .expect("blocking thread error")
    }

    /// Remove an entry (and all chunk references).
    ///
    /// Returns the ids of the deleted chunks' blobs so the file stores can
    /// be removed.
    pub async fn rm(
        &self,
        class: String,
        key: String,
    ) -> Result<Vec<[u8; 32]>> {
        let c_write = self.c_write.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_write = c_write.lock().unwrap();
            let tx = c_write
                .transaction_with_behavior(
                    rusqlite::TransactionBehavior::Exclusive,
                )
                .map_err(std::io::Error::other)?;
            let mut out: Vec<[u8; 32]> = Vec::new();
            for blob_id in tx
                .prepare(
                    "
SELECT blob_id
FROM entry_file_chunks
WHERE class = ?1 AND key = ?2;
            ",
                )
                .map_err(std::io::Error::other)?
                .query_map(rusqlite::params![&class, &key], |row| row.get(0))
                .map_err(std::io::Error::other)?
            {
                out.push(blob_id.map_err(std::io::Error::other)?);
            }
            tx.execute(
                "
DELETE FROM entries
WHERE class = ?1 AND key = ?2;
            ",
                rusqlite::params![class, key],
            )
            .map_err(std::io::Error::other)?;
            tx.commit().map_err(std::io::Error::other)?;
            Ok(out)
        })
        .await
        .expect("blocking thread error")
    }

    /// Remove a bounded batch of entries that expired at or before
    /// `now_micros`.
    ///
    /// Returns the number of entries removed alongside the ids of their
    /// chunks' blobs so the file stores can be removed. A return count equal
    /// to `limit` means there may be more expired entries waiting.
    pub async fn prune_expired(
        &self,
        now_micros: i64,
        limit: i64,
    ) -> Result<(usize, Vec<[u8; 32]>)> {
        let c_write = self.c_write.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_write = c_write.lock().unwrap();
            let tx = c_write
                .transaction_with_behavior(
                    rusqlite::TransactionBehavior::Exclusive,
                )
                .map_err(std::io::Error::other)?;

            let mut blob_ids: Vec<[u8; 32]> = Vec::new();
            for blob_id in tx
                .prepare(PRUNE_EXPIRED_BLOB_IDS)
                .map_err(std::io::Error::other)?
                .query_map(rusqlite::params![now_micros, limit], |row| {
                    row.get(0)
                })
                .map_err(std::io::Error::other)?
            {
                blob_ids.push(blob_id.map_err(std::io::Error::other)?);
            }

            let count = tx
                .execute(PRUNE_EXPIRED, rusqlite::params![now_micros, limit])
                .map_err(std::io::Error::other)?;

            tx.commit().map_err(std::io::Error::other)?;

            Ok((count, blob_ids))
        })
        .await
        .expect("blocking thread error")
    }

    /// Get an entry.
    pub async fn get(
        &self,
        class: String,
        key: String,
    ) -> Result<Option<super::VmIoDbEntry>> {
        let c_read_pool = self.c_read_pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_read = c_read_pool.get();
            let tx = c_read.transaction().map_err(std::io::Error::other)?;
            match tx.query_one(
                GET_ENTRY,
                rusqlite::params![class, key],
                |row| {
                    Ok(super::VmIoDbEntry {
                        class: class.to_string(),
                        key: key.to_string(),
                        modified_at_micros: row.get(0)?,
                        expires_at_micros: row.get(1)?,
                        metadata: row.get(2)?,
                        chunk_count: row.get(3)?,
                    })
                },
            ) {
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(std::io::Error::other(err)),
                Ok(entry) => Ok(Some(entry)),
            }
        })
        .await
        .expect("blocking thread error")
    }

    /// Get an entry file chunk.
    pub async fn get_chunk(
        &self,
        class: String,
        key: String,
        idx: i64,
    ) -> Result<Option<Chunk>> {
        let c_read_pool = self.c_read_pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_read = c_read_pool.get();
            let tx = c_read.transaction().map_err(std::io::Error::other)?;

            match tx.query_one(
                GET_CHUNK,
                rusqlite::params![class, key, idx],
                |row| {
                    Ok(Chunk {
                        hash: row.get(0)?,
                        tag: row.get(1)?,
                        size: row.get(2)?,
                        is_final: row.get(3)?,
                    })
                },
            ) {
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(std::io::Error::other(err)),
                Ok(chunk) => Ok(Some(chunk)),
            }
        })
        .await
        .expect("blocking thread error")
    }

    /// List entries.
    pub async fn list(
        &self,
        class: String,
        filter: super::VmIoDbListFilter,
        sort: super::VmIoDbListSort,
        limit: i64,
    ) -> Result<Vec<super::VmIoDbEntry>> {
        let c_read_pool = self.c_read_pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut c_read = c_read_pool.get();
            let tx = c_read.transaction().map_err(std::io::Error::other)?;

            let mut params: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(class.clone())];

            let mut list_sql = "
SELECT
  key,
  modified_at_micros,
  expires_at_micros,
  metadata,
  (
    SELECT COUNT(idx)
    FROM entry_file_chunks
    WHERE class = entries.class AND key = entries.key
  ) AS chunk_count
FROM entries
WHERE class = ?1"
                .to_string();

            match filter {
                super::VmIoDbListFilter::All => (),
                super::VmIoDbListFilter::KeyPrefix(prefix) => {
                    params.push(Box::new(glob_prefix_pattern(&prefix)));
                    list_sql
                        .push_str(&format!(" AND key GLOB ?{}", params.len()));
                }
                super::VmIoDbListFilter::ModifiedAtMicrosRange {
                    start,
                    end,
                } => {
                    list_sql.push_str(" AND modified_at_micros");
                    match start {
                        std::ops::Bound::Unbounded => {
                            params.push(Box::new(0_i64));
                            list_sql.push_str(&format!(" >= ?{}", params.len()))
                        }
                        std::ops::Bound::Included(t) => {
                            params.push(Box::new(t));
                            list_sql.push_str(&format!(" >= ?{}", params.len()))
                        }
                        std::ops::Bound::Excluded(t) => {
                            params.push(Box::new(t));
                            list_sql.push_str(&format!(" > ?{}", params.len()))
                        }
                    }
                    list_sql.push_str(" AND modified_at_micros");
                    match end {
                        std::ops::Bound::Unbounded => {
                            params.push(Box::new(9223372036854775807_i64));
                            list_sql.push_str(&format!(" <= ?{}", params.len()))
                        }
                        std::ops::Bound::Included(t) => {
                            params.push(Box::new(t));
                            list_sql.push_str(&format!(" <= ?{}", params.len()))
                        }
                        std::ops::Bound::Excluded(t) => {
                            params.push(Box::new(t));
                            list_sql.push_str(&format!(" < ?{}", params.len()))
                        }
                    }
                }
            }

            match sort {
                super::VmIoDbListSort::KeyAsc => {
                    list_sql.push_str(" ORDER BY class ASC, key ASC")
                }
                super::VmIoDbListSort::KeyDesc => {
                    list_sql.push_str(" ORDER BY class DESC, key DESC")
                }
                super::VmIoDbListSort::ModifiedAtMicrosAsc => {
                    list_sql.push_str(" ORDER BY modified_at_micros ASC")
                }
                super::VmIoDbListSort::ModifiedAtMicrosDesc => {
                    list_sql.push_str(" ORDER BY modified_at_micros DESC")
                }
            }

            params.push(Box::new(limit));
            list_sql.push_str(&format!(" LIMIT ?{}", params.len()));

            let ref_params: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|b| b.as_ref()).collect();

            let mut out: Vec<super::VmIoDbEntry> = Vec::new();
            for entry in tx
                .prepare(&list_sql)
                .map_err(std::io::Error::other)?
                .query_map(ref_params.as_slice(), |row| {
                    Ok(super::VmIoDbEntry {
                        class: class.to_string(),
                        key: row.get(0)?,
                        modified_at_micros: row.get(1)?,
                        expires_at_micros: row.get(2)?,
                        metadata: row.get(3)?,
                        chunk_count: row.get(4)?,
                    })
                })
                .map_err(std::io::Error::other)?
            {
                out.push(entry.map_err(std::io::Error::other)?);
            }

            Ok(out)
        })
        .await
        .expect("blocking thread error")
    }
}

/// A database entry file chunk.
pub struct Chunk {
    /// sha256 hash of chunk content
    pub hash: [u8; 32],

    /// aegis256 tag
    pub tag: [u8; 32],

    /// content size
    pub size: i64,

    /// is this the last file chunk?
    pub is_final: bool,
}

struct RingPool<T> {
    checkout_rx: Mutex<std::sync::mpsc::Receiver<T>>,
    return_tx: std::sync::mpsc::Sender<T>,
}

struct PoolGuard<T> {
    item: Option<T>,
    return_tx: std::sync::mpsc::Sender<T>,
}

impl<T> RingPool<T> {
    pub fn new(a: T, b: T, c: T) -> Self {
        let (return_tx, checkout_rx) = std::sync::mpsc::channel();

        return_tx.send(a).unwrap();
        return_tx.send(b).unwrap();
        return_tx.send(c).unwrap();

        Self {
            checkout_rx: Mutex::new(checkout_rx),
            return_tx,
        }
    }

    pub fn get(&self) -> PoolGuard<T> {
        let item = self.checkout_rx.lock().unwrap().recv().ok();
        PoolGuard {
            item,
            return_tx: self.return_tx.clone(),
        }
    }
}

impl<T> std::ops::Deref for PoolGuard<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.item.as_ref().unwrap()
    }
}

impl<T> std::ops::DerefMut for PoolGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.item.as_mut().unwrap()
    }
}

impl<T> Drop for PoolGuard<T> {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            let _ = self.return_tx.send(item);
        }
    }
}
