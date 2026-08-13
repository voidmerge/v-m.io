# store-vm

store-vm is initially a library to be built into an application binary that provides storage for opaque byte array blobs.

The data is keyed and indexed in the following manner:

- primary string key
- f64 index (must be a finite f64)

The data that is stored includes:

- metadata string
- the byte array blob

On a write, if there is an existing primary string key in the store, the write is accepted only if the f64 index is greater than the existing entry's f64 index.

e.g. the (primary string key, f64) might be: `("c/context/my~app~path", 3.14159)` and store the data: `("3.14159/0/5", b"hello")`.

The library provides the ability to make range queries with prefixes on the keys.

An implementation could execute a list command like: list up to 32 primary string keys, f64 indexes and metadata strings with f64 index > 2.22 and a primary string key that starts with "c/context/my~app~".

At a later date, store-vm will also be a standalone binary with a REST api that will allow multiple front-ends to use the same backing store.

## Requirements

- Platform
    - This is designed to be written in rust, so should have a mature and well maintained integration with that language.
    - This is designed to run cross platform, so should be reliable and straight forward to compile whether on Linux, MacOs, or Windows.
- Reliability
    - If the process crashes mid-write, the store should be left uncorrupted and the entry that was mid-write should not exist in the store (orphaned data written to disk can be cleaned up on a slower timeline via some background thread).
    - If the write process returns a success, even if there is a crash immediately after, the store should be left uncorrupted and the entry that completed should exist in the store.
- Concurrency
    - Thread safety: The library should allow multiple threads to read and write to the store concurrently.
    - Process safety: The library should allow multiple processes to read and write to the store concurrently.
    - Network safety: It is NOT a requirement that the library should work correctly on a network mounted file system. If possible, the library should detect this condition and refuse to function.
- Limiting RAM usage
    - The byte array blobs can be any size from one byte to multiple gigabytes. We should take advantage of efficiencies in os disk caching using direct file access for returning the byte array contents, storing the file path along with the metadata string, except in the edge case of a zero byte byte array, which will get a null file path.
- Blob files
    - Blob file naming
        - get a sha256 of the primary string key and f64 index
        - base16 (hexadecimal) encode it.
        - within the `root_path` directory,
        - mkdir -p a directory path named `{hex[..4]}/{hex[4..8]}/{hex[8..12]}`
        - then store a file with the full sha256 hex filename.
    - When writing, if this object *should* be written,
      (either the `primary_string_key` does not exist yet, or it exists but
      this f64 index is > than the existing one), Then the following process
      will be followed:
        - the blob file for this entry will be written
        - on success of the above, an atomic (exclusive write) operation
          will be started to update the key. This operation will again
          check the `primary_string_key` and f64 index requirements,
          if those pass, the key/index will be updated. If not,
          the blob file will be deleted.
- StoreVm sharing model
    - The rust `StoreVm` instance should be `'static + Send + Sync`.
    - The methods on `StoreVm` should take `&self`.
    - A user of the instance can wrap it in an `Arc` to share it across tasks.

## Example Rust API

```rust
/// The combined key for an entry.
#[derive(Debug, Clone)]
pub struct Key {
    /// The primary string key.
    pub primary_string_key: Arc<str>,

    /// The f64 index.
    pub index: f64,
}

/// Metadata string type.
pub type MetadataString = Arc<str>;

/// Byte array type.
pub type Reader = Box<dyn tokio::io::AsyncRead + 'static + Send>;

/// The [StoreVm] struct provides backing object/document storage.
pub struct StoreVm {
    // internal members here
}

impl StoreVm {
    /// Create a new [StoreVm] instance.
    /// The root path will contain:
    /// - `key_db.sqlite` - the sqlite file storing the key database/indexes.
    /// - `data` - a directory containing the byte array files.
    pub async fn new(root_path: impl AsRef<std::path::Path>) -> Result<Self>;

    /// Get the current object by path from the store.
    pub async fn get(&self, primary_string_key: Arc<str>) -> Result<(Key, MetadataString, Reader)>>;

    /// Delete a specific object by from the store.
    /// This operation first removes the index from the sqlite database,
    /// then deletes any byte array file associated with it.
    pub async fn rm(&self, key: Key) -> Result<()>;

    /// List objects in the store by path prefix.
    pub async fn list(
        &self,
        path_prefix: Arc<str>,
        index_greater_than: f64,
        limit: u32,
    ) -> Result<Vec<(Key, MetadataString)>>;

    /// Put an object into the store.
    pub async fn put(&self, key: Key, metadata: MetadataString, data: Reader) -> Result<()>;
}
```

## sqlite (rusqlite)

We will be using sqlite via the rusqlite library for the key and metadata storage/indexing.

### Potential sqlite schema

```sql
CREATE TABLE entries (
    primary_key TEXT NOT NULL PRIMARY KEY,
    idx         REAL NOT NULL,
    metadata    TEXT NOT NULL,
    blob_path   TEXT           -- NULL for zero-byte blobs
);
CREATE INDEX entries_prefix_idx ON entries (primary_key, idx);
```

### Possible sqlite pragmas to satisfy requirements

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;  -- safe with WAL, good perf
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;   -- handles multi-process write contention gracefully
```

## Orphan Blob Garbage Collection

Blob files can be left on disk with no corresponding DB entry in two scenarios:

1. **Crash mid-write**: the blob was written to disk but the process died before
   `put_if_newer` committed the DB entry.
2. **Write race**: two concurrent `put` calls wrote the same (key, idx) blob;
   the loser cleaned up its blob, but the cleanup `remove` itself crashed.

Because `put` always writes the blob *before* committing to the DB, there is
always a brief window during a healthy write where the blob exists on disk with
no DB entry. Any GC that naively deletes unreferenced blobs will corrupt
in-progress writes.

### Safety: mtime threshold

Before treating a blob as an orphan candidate, check that its file modification
time is older than a configurable threshold (default: **5 minutes**). Any
in-progress write will have a recent mtime. Any crash-orphan will have an old
mtime long before the GC runs. The threshold only needs to exceed any realistic
blob write duration and is intentionally conservative.

### Algorithm: filesystem-first batch scan

No new database index is added. The GC runs infrequently enough that a full
table scan per batch is acceptable (a 100 K-row SQLite scan takes ~5 ms).
Adding a `blob_path` index would impose ongoing write overhead for a marginal
gain in GC speed.

**Steps (runs as a long-lived background async task):**

1. Recursively walk the `data/` directory tree using async `read_dir`, collecting
   blob file paths into batches of N (default: **200**).
2. For each batch, discard any path whose `mtime` is newer than the orphan
   threshold — these are potentially in-flight writes and must not be touched.
3. Query the DB for the batch:
   ```sql
   SELECT blob_path FROM entries WHERE blob_path IN (?, ..., ?)
   ```
4. Delete every path in the batch that was **not** returned by the query — these
   are confirmed orphans.
5. Sleep briefly between batches (default: **250 ms**) to avoid saturating disk
   I/O and CPU, then continue to the next batch.
6. After the full walk completes, sleep for the configured GC interval (default:
   **1 hour**) before starting the next full walk.

### API shape

The GC is exposed as a cancellation-friendly method on `StoreVm`. The caller
drives the loop and owns the cancellation token, typically via `tokio::select!`:

```rust
impl StoreVm {
    /// Run one full GC pass: walk the blob directory, remove orphans.
    /// Returns when the pass is complete. Call in a loop with an outer
    /// sleep/interval for periodic execution.
    pub async fn gc_pass(&self) -> Result<GcStats, StoreVmError>;
}

pub struct GcStats {
    pub blobs_scanned: u64,
    pub blobs_deleted: u64,
}
```

### Why not a sorted merge join?

A merge join between a sorted DB cursor and a sorted filesystem walk would
achieve O(1) memory per step, but requires sorting `readdir` output at every
directory level and adds significant implementation complexity. The batch-scan
approach with a full table scan per batch is simpler, correct, and fast enough
for an infrequent background task.

### Why not a Bloom filter?

A Bloom filter over all `blob_path` values would reduce DB queries to near-zero
for large stores, but adds implementation complexity and non-trivial memory usage
for stores with millions of entries. The batch-scan approach is sufficient.
