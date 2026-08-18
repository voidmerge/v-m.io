#![deny(missing_docs)]
//! v-m.io all service runtime database

use sha2::Digest;
use std::io::Result;
use std::sync::Arc;

mod blob;
mod sql;

/// Database entry.
pub struct VmIoDbEntry {
    /// entry class identifier
    pub class: String,

    /// entry key identifier
    pub key: String,

    /// entry created at timestamp in microseconds
    pub modified_at_micros: i64,

    /// if specified, entry will be pruned after this timestamp in microseconds
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
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
    task: tokio::task::AbortHandle,
}

impl Drop for VmIoDb {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn cleanup_task(
    root_dir: std::path::PathBuf,
    sql: Arc<sql::Sql>,
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
) {
    loop {
        // TODO - loop over hash files, checking for references in sql,
        //        (add hash index to sql??)
        //        any unreferenced files with system modified times
        //        > 1 minute should be safe to delete

        // TODO - walk the directory (part of same loop above??) any
        //        empty hash directory with a modified time > 1 minute
        //        should be safe to remove

        tokio::time::sleep(std::time::Duration::from_secs(60 * 10)).await;
    }
}

impl VmIoDb {
    /// Construct a new database.
    pub async fn new<P: Into<std::path::PathBuf>>(
        root_dir: P,
        encryption_key: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let root_dir = root_dir.into();
        tokio::fs::create_dir_all(&root_dir).await?;

        let mut sql_path = root_dir.clone();
        sql_path.push("db.sqlite");

        let sql =
            Arc::new(sql::Sql::new(sql_path, encryption_key.clone()).await?);

        let task = tokio::task::spawn(cleanup_task(
            root_dir.clone(),
            sql.clone(),
            encryption_key.clone(),
        ))
        .abort_handle();

        Ok(Self {
            root_dir,
            sql,
            encryption_key: encryption_key.into(),
            task,
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

        let blob::EncryptResult { nonce, tag } = blob::encrypt_chunk(
            &class,
            &key,
            idx,
            &mut data[..],
            &hash,
            &self.encryption_key,
            is_final,
        )?;

        let path = blob::gen_path(&self.root_dir, &class, &key, idx, &hash);
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        tokio::fs::write(&path, &data).await?;

        match self
            .sql
            .upsert_chunk(
                class,
                key,
                idx,
                hash,
                nonce,
                tag,
                data.len() as i64,
                is_final,
            )
            .await
        {
            Err(err) => {
                let _ = tokio::fs::remove_file(&path).await;
                Err(err)
            }
            Ok(_) => {
                // TODO - upsert_chunk should return the old hash
                //        if it was replaced so we can delete it here
                Ok(())
            }
        }
    }

    /// Remove an entry.
    pub async fn rm(&self, class: String, key: String) -> Result<()> {
        let chunks = self.sql.rm(class.clone(), key.clone()).await?;
        for chunk in chunks {
            let path = blob::gen_path(
                &self.root_dir,
                &class,
                &key,
                chunk.idx,
                &chunk.hash,
            );
            tokio::fs::remove_file(path).await?;
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

        let path =
            blob::gen_path(&self.root_dir, &class, &key, idx, &chunk.hash);
        let mut data = tokio::fs::read(path).await?;

        if data.len() != chunk.size as usize {
            return Err(std::io::Error::other("corrupted chunk"));
        }

        blob::decrypt_chunk(
            &class,
            &key,
            idx,
            &mut data[..],
            &chunk.hash,
            &self.encryption_key,
            is_final,
            &chunk.nonce,
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
