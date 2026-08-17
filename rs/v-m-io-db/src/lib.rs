#![deny(missing_docs)]
//! v-m.io all service runtime database

use sha2::Digest;
use std::io::Result;

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

/// Database list result.
pub struct VmIoDbListResult {
    /// entry class identifier
    pub class: String,

    /// entry key identifier
    pub key: String,
}

/// v-m.io all service runtime database
pub struct VmIoDb {
    root_dir: std::path::PathBuf,
    sql: sql::Sql,
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
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

        let sql = sql::Sql::new(sql_path, encryption_key.clone()).await?;

        Ok(Self {
            root_dir,
            sql,
            encryption_key: encryption_key.into(),
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

        let path = blob::gen_path(&self.root_dir, &class, &key, idx, &hash);
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;

        let blob::EncryptResult { nonce, tag } = blob::encrypt_chunk(
            &class,
            &key,
            idx,
            &mut data[..],
            &hash,
            &self.encryption_key,
            is_final,
        )?;

        self.sql
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
            .await?;

        tokio::fs::write(path, &data).await?;

        Ok(())
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

        let c = db
            .get_chunk("c".into(), "k".into(), 0, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!("hello", String::from_utf8_lossy(&c));

        db.rm("c".into(), "k".into()).await.unwrap();
    }
}
