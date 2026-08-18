use rand::RngExt;
use sha2::Digest;
use std::io::Result;

/// Count of shard directory levels between the root and a blob file.
pub const SHARD_DEPTH: usize = 3;

/// Length of a single shard directory name.
const SHARD_LEN: usize = 4;

/// Identifier of the blob file backing a single entry file chunk.
///
/// This is stored alongside the chunk row so the cleanup task can map a
/// file found on disk back to the row that references it.
pub fn gen_id(class: &str, key: &str, idx: i64, hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(class.as_bytes());
    hasher.update(key.as_bytes());
    hasher.update(idx.to_le_bytes());
    hasher.update(hash);
    hasher.finalize().into()
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

pub fn gen_path(
    root_dir: &std::path::Path,
    class: &str,
    key: &str,
    idx: i64,
    hash: &[u8; 32],
) -> std::path::PathBuf {
    id_path(root_dir, &gen_id(class, key, idx, hash))
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

fn make_adata(
    class: &str,
    key: &str,
    idx: i64,
    hash: &[u8; 32],
    is_final: bool,
) -> Vec<u8> {
    let mut adata =
        format!("{}\0{}\0{}\0{}\0", class, key, idx, is_final,).into_bytes();
    adata.extend_from_slice(hash);
    adata
}

fn derive_sub_key(
    idx: i64,
    hash: &[u8; 32],
    encryption_key: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;

    let hk =
        Hkdf::<sha2::Sha256>::new(Some(&idx.to_le_bytes()), encryption_key);
    let mut sub_key = [0_u8; 32];
    hk.expand(hash, &mut sub_key).unwrap();

    sub_key
}

pub struct EncryptResult {
    pub nonce: [u8; 32],
    pub tag: [u8; 32],
}

pub fn encrypt_chunk(
    class: &str,
    key: &str,
    idx: i64,
    data: &mut [u8],
    hash: &[u8; 32],
    encryption_key: &[u8; 32],
    is_final: bool,
) -> Result<EncryptResult> {
    let sub_key = derive_sub_key(idx, hash, encryption_key);

    let mut nonce = [0; 32];
    rand::rng().fill(&mut nonce);
    let adata = make_adata(class, key, idx, hash, is_final);

    let enc = <aegis::aegis256::Aegis256<32>>::new(&sub_key, &nonce);
    let tag = enc.encrypt_in_place(data, &adata);

    Ok(EncryptResult { nonce, tag })
}

pub fn decrypt_chunk(
    class: &str,
    key: &str,
    idx: i64,
    data: &mut [u8],
    hash: &[u8; 32],
    encryption_key: &[u8; 32],
    is_final: bool,
    nonce: &[u8; 32],
    tag: &[u8; 32],
) -> Result<()> {
    let sub_key = derive_sub_key(idx, hash, encryption_key);

    let adata = make_adata(class, key, idx, hash, is_final);

    let dec = <aegis::aegis256::Aegis256<32>>::new(&sub_key, nonce);

    dec.decrypt_in_place(data, tag, &adata)
        .map_err(std::io::Error::other)
}
