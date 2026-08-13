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
const GET_ENTRY: &str = include_str!("sql/get_entry.sql");
const GET_CHUNK_COUNT: &str = include_str!("sql/get_chunk_count.sql");

pub fn sqlite_key(
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

/// sqlite db connection
pub struct Sql {
    c_write: Arc<Mutex<rusqlite::Connection>>,
    c_read_pool: Arc<RingPool<rusqlite::Connection>>,
}

impl Sql {
    /// Construct a new db connection pool.
    pub async fn new<P: Into<std::path::PathBuf>>(
        path: P,
        encryption_key: zeroize::Zeroizing<[u8; 32]>,
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

            let hex_key = sqlite_key(&encryption_key);
            let hex_key = std::str::from_utf8(&hex_key[..]).unwrap();

            c_write
                .pragma_update(None, "key", &hex_key)
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
                .pragma_update(None, "key", &hex_key)
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
                .pragma_update(None, "key", &hex_key)
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
                .pragma_update(None, "key", &hex_key)
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
    pub async fn upsert_chunk(
        &self,
        class: String,
        key: String,
        idx: i64,
        hash: [u8; 32],
        nonce: [u8; 32],
        tag: [u8; 32],
        size: i64,
        last: bool,
    ) -> Result<()> {
        todo!()
    }

    /// Remove an entry (and all chunk references).
    ///
    /// Returns a list of deleted chunks so the file stores can be removed.
    pub async fn rm(&self, class: &str, key: &str) -> Result<Vec<Chunk>> {
        todo!()
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

            let mut entry = match tx.query_one(
                GET_ENTRY,
                rusqlite::params![class, key],
                |row| {
                    Ok(super::VmIoDbEntry {
                        class: class.clone(),
                        key: key.clone(),
                        modified_at_micros: row.get(0)?,
                        expires_at_micros: row.get(1)?,
                        metadata: row.get(2)?,
                        chunk_count: 0,
                    })
                },
            ) {
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(err) => return Err(std::io::Error::other(err)),
                Ok(entry) => entry,
            };

            if let Ok(count) = tx.query_one(
                GET_CHUNK_COUNT,
                rusqlite::params![class, key],
                |row| row.get::<_, i64>(0),
            ) {
                entry.chunk_count = count;
            }

            Ok(Some(entry))
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
        todo!()
    }

    /// List entries.
    pub async fn list(
        &self,
        class: &str,
        filter: ListFilter,
        sort: ListSort,
        limit: i64,
    ) -> Result<Vec<super::VmIoDbListResult>> {
        todo!()
    }
}

/// Specify how the list should be filtered.
pub enum ListFilter {
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
pub enum ListSort {
    /// default sorting by key ascending
    KeyAsc,

    /// default sorting by key descending
    KeyDesc,

    /// by modified_at_micros ascending
    ModifiedAtMicrosAsc,

    /// by modified_at_micros descending
    ModifiedAtMicrosDesc,
}

/// A database entry file chunk.
pub struct Chunk {
    /// sha256 hash of chunk content
    pub hash: [u8; 32],

    /// aegis256 nonce
    pub nonce: [u8; 32],

    /// aegis256 tag
    pub tag: [u8; 32],

    /// content size
    pub size: i64,

    /// is this the last file chunk?
    pub last: bool,
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
