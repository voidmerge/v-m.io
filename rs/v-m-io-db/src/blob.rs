use rand::RngExt;
use sha2::Digest;
use std::io::Result;

pub fn gen_path(
    root_dir: &std::path::Path,
    class: &str,
    key: &str,
    idx: i64,
    hash: &[u8; 32],
) -> std::path::PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(class.as_bytes());
    hasher.update(key.as_bytes());
    hasher.update(idx.to_le_bytes());
    hasher.update(hash);
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    root_dir
        .join(&hex[..4])
        .join(&hex[4..8])
        .join(&hex[8..12])
        .join(&hex)
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
