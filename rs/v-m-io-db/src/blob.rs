use std::io::Result;

/// Count of shard directory levels between the root and a blob file.
pub const SHARD_DEPTH: usize = 3;

/// Length of a single shard directory name.
const SHARD_LEN: usize = 4;

/// Domain separation labels for the chunk key schedule.
///
/// Each derived output gets its own label so the outputs are computationally
/// independent. The id in particular is published as a filename, so it must
/// reveal nothing about the key or nonce derived from the same identity.
const INFO_ID: &[u8] = b"v-m.io blob id v1";
const INFO_KEY: &[u8] = b"v-m.io blob key v1";
const INFO_NONCE: &[u8] = b"v-m.io blob nonce v1";

/// Everything about an entry file chunk that its blob is bound to.
pub struct ChunkId<'a> {
    /// entry class identifier
    pub class: &'a str,

    /// entry key identifier
    pub key: &'a str,

    /// chunk index
    pub idx: i64,

    /// sha256 hash of the chunk plaintext
    pub hash: &'a [u8; 32],

    /// is this the last chunk of the file?
    pub is_final: bool,
}

/// Key schedule for one chunk's blob, derived by [ChunkId::derive].
struct ChunkKeys {
    /// names the blob file on disk
    id: [u8; 32],

    /// aegis256 key
    key: zeroize::Zeroizing<[u8; 32]>,

    /// aegis256 nonce
    nonce: [u8; 32],

    /// aegis256 associated data
    adata: Vec<u8>,
}

impl ChunkId<'_> {
    /// Length framed encoding of this chunk identity.
    ///
    /// Every variable length field is length prefixed, which makes the
    /// encoding injective - distinct identities cannot encode to the same
    /// bytes. Plain concatenation cannot promise that: class "a" with key "b"
    /// and class "ab" with an empty key both concatenate to "ab", which would
    /// hand two unrelated entries the same blob file.
    fn frame(&self) -> Vec<u8> {
        let class = self.class.as_bytes();
        let key = self.key.as_bytes();

        let mut out =
            Vec::with_capacity(8 + class.len() + 8 + key.len() + 8 + 32 + 1);

        out.extend_from_slice(&(class.len() as u64).to_le_bytes());
        out.extend_from_slice(class);
        out.extend_from_slice(&(key.len() as u64).to_le_bytes());
        out.extend_from_slice(key);

        // fixed width from here on, so no length prefixes are needed
        out.extend_from_slice(&self.idx.to_le_bytes());
        out.extend_from_slice(self.hash);
        out.push(self.is_final as u8);

        out
    }

    /// Derive this chunk's blob id, key, nonce and associated data.
    fn derive(&self, blob_key: &[u8; 32]) -> ChunkKeys {
        use hkdf::Hkdf;

        let adata = self.frame();

        // the framed identity is the salt, so the extracted prk is already
        // bound to this one chunk, with the blob sub key as the ikm
        let hk = Hkdf::<sha2::Sha256>::new(Some(&adata), blob_key);

        let mut keys = ChunkKeys {
            id: [0; 32],
            key: zeroize::Zeroizing::new([0; 32]),
            nonce: [0; 32],
            adata,
        };

        // expand only fails on absurd output lengths
        hk.expand(INFO_ID, &mut keys.id).unwrap();
        hk.expand(INFO_KEY, &mut *keys.key).unwrap();
        hk.expand(INFO_NONCE, &mut keys.nonce).unwrap();

        keys
    }
}

/// Identifier of the blob file backing a single entry file chunk.
///
/// This is stored alongside the chunk row so the cleanup task can map a file
/// found on disk back to the row that references it. It is derived under the
/// blob sub key, so it cannot be predicted from the entry identity and content
/// alone - an attacker holding the directory but not the key cannot confirm a
/// guessed chunk by checking whether its filename exists.
pub fn gen_id(chunk: &ChunkId, blob_key: &[u8; 32]) -> [u8; 32] {
    chunk.derive(blob_key).id
}

/// Path of the blob file with the given id.
pub fn id_path(
    root_dir: &std::path::Path,
    id: &[u8; 32],
) -> std::path::PathBuf {
    let hex = hex::encode(id);
    root_dir
        .join(&hex[..SHARD_LEN])
        .join(&hex[SHARD_LEN..SHARD_LEN * 2])
        .join(&hex[SHARD_LEN * 2..SHARD_LEN * 3])
        .join(&hex)
}

/// Is this the name of a shard directory in the blob layout?
pub fn is_shard_name(name: &str) -> bool {
    name.len() == SHARD_LEN && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a blob file name back into the blob id it encodes.
pub fn parse_name(name: &str) -> Option<[u8; 32]> {
    let mut id = [0; 32];
    hex::decode_to_slice(name, &mut id).ok()?;
    Some(id)
}

/// Write a blob file, creating its shard directories as needed.
pub async fn write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    // the cleanup task removes empty shard directories, and can do so
    // between our create_dir_all and our write, so retry once
    for _ in 0..2 {
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        match tokio::fs::write(path, data).await {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            res => return res,
        }
    }
    Err(std::io::Error::other("blob shard removed during write"))
}

/// Result of [encrypt_chunk].
pub struct EncryptResult {
    /// names the blob file the ciphertext belongs at
    pub id: [u8; 32],

    /// aegis256 tag, to be stored in sql
    pub tag: [u8; 32],
}

/// Encrypt a chunk in place.
///
/// The nonce is derived rather than random, which makes the ciphertext a pure
/// function of the chunk identity: writing the same chunk twice produces
/// byte identical output at a byte identical path, so a blob file is never
/// meaningfully rewritten. That is what lets [crate::VmIoDb::upsert_chunk]
/// treat blobs as write once.
///
/// A derived nonce is safe here because the key is derived from the same
/// identity, which includes the plaintext hash. Equal key and nonce therefore
/// implies equal plaintext, so the pair can never be reused across differing
/// plaintexts - the one thing an AEAD nonce must rule out.
pub fn encrypt_chunk(
    chunk: &ChunkId,
    data: &mut [u8],
    blob_key: &[u8; 32],
) -> EncryptResult {
    let keys = chunk.derive(blob_key);

    let enc = <aegis::aegis256::Aegis256<32>>::new(&keys.key, &keys.nonce);
    let tag = enc.encrypt_in_place(data, &keys.adata);

    EncryptResult { id: keys.id, tag }
}

/// Decrypt a chunk in place, verifying it against `tag`.
pub fn decrypt_chunk(
    chunk: &ChunkId,
    data: &mut [u8],
    blob_key: &[u8; 32],
    tag: &[u8; 32],
) -> Result<()> {
    let keys = chunk.derive(blob_key);

    let dec = <aegis::aegis256::Aegis256<32>>::new(&keys.key, &keys.nonce);

    dec.decrypt_in_place(data, tag, &keys.adata)
        .map_err(std::io::Error::other)
}
