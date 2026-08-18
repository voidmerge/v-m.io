use zeroize::Zeroizing;

/// Domain separation labels for the top level key split.
const INFO_SQLITE: &[u8] = b"v-m.io sqlite key v1";
const INFO_BLOB: &[u8] = b"v-m.io blob root key v1";

/// Independent sub keys derived from the caller's master key.
///
/// The master key is never handed to a cryptosystem directly. Each consumer
/// gets its own sub key, so sqlcipher's key derivation and the blob key
/// schedule share no key material and cannot interact. Once this split is
/// taken the master key is dropped, and with it zeroized.
pub struct RootKeys {
    /// sqlcipher database key
    pub sqlite: Zeroizing<[u8; 32]>,

    /// ikm for the per chunk blob key schedule
    pub blob: Zeroizing<[u8; 32]>,
}

impl RootKeys {
    /// Split a master key into its per consumer sub keys.
    pub fn derive(master: &Zeroizing<[u8; 32]>) -> Self {
        // no salt: the master is already a uniform 32 byte key, so extract
        // has no entropy to concentrate, and the labels below are what
        // separate the outputs
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &master[..]);

        let mut out = Self {
            sqlite: Zeroizing::new([0; 32]),
            blob: Zeroizing::new([0; 32]),
        };

        // expand only fails on absurd output lengths
        hk.expand(INFO_SQLITE, &mut *out.sqlite).unwrap();
        hk.expand(INFO_BLOB, &mut *out.blob).unwrap();

        out
    }
}
