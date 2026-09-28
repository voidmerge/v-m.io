//! API types.

const CONFIG: bincode_next::config::Configuration =
    bincode_next::config::standard();

/// Config value tombstone marker.
pub const CONFIG_TOMBSTONE: &str = "\x1f[[::TOMBSTONE::]]\x04";

// ## WARNING - CRITICAL ##
//
// We're using bincode here, which doesn't use tags...
// - you can only add #[serde(default)] fields to the end of structs or
//   enum variants
// - you cannot re-order enum variant fields, variants themselves, nor
//   fields within structs
// - only add new variants to the end of enums or fields within structs

/// Encode to bytes.
pub fn encode<E>(e: &E) -> std::io::Result<Vec<u8>>
where
    E: std::fmt::Debug + serde::Serialize,
{
    bincode_next::serde::encode_to_vec(e, CONFIG).map_err(std::io::Error::other)
}

/// Decode from bytes.
pub fn decode<D>(slice: &[u8]) -> std::io::Result<D>
where
    D: std::fmt::Debug + serde::de::DeserializeOwned,
{
    bincode_next::serde::decode_from_slice(slice, CONFIG)
        .map_err(std::io::Error::other)
        .map(|(o, _)| o)
}

/// `cfg-get` request payload.
pub type CfgGetReq = ();

/// A single `cfg-get` response entry.
///
/// Carries the entry metadata alongside its value so the response can be used
/// to synchronize config state between backend server nodes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CfgGetItem {
    /// The config entry key.
    pub key: String,
    /// The config entry value.
    pub value: String,
    /// The entry's last-modified unix epoch timestamp in microseconds.
    pub modified_at_micros: i64,
    /// Optional expiration time, as a unix epoch timestamp in microseconds.
    ///
    /// `None` leaves the entry without an expiry.
    #[serde(default)]
    pub expires_at_micros: Option<i64>,
}

/// `cfg-get` response payload.
pub type CfgGetRes = Result<Vec<CfgGetItem>, String>;

/// `cfg-put` request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CfgPutReq {
    /// The config entry key.
    pub key: String,
    /// The config entry value.
    pub value: String,
    /// Optional expiration time, as a unix epoch timestamp in microseconds.
    ///
    /// `None` leaves the entry without an expiry.
    #[serde(default)]
    pub expires_at_micros: Option<i64>,
    /// Optional last-modified time, as a unix epoch timestamp in
    /// microseconds.
    ///
    /// `None` lets the server assign the current time. An explicit value is
    /// used as-is, allowing a node to apply an entry synced from a peer while
    /// preserving the peer's ordering.
    ///
    /// Appended after [`Self::expires_at_micros`] to keep the bincode field
    /// order append-only.
    #[serde(default)]
    pub modified_at_micros: Option<i64>,
}

/// `cfg-put` response payload.
pub type CfgPutRes = ();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let enc: CfgGetRes = Ok(vec![
            CfgGetItem {
                key: "test1".to_string(),
                value: "1".to_string(),
                modified_at_micros: 10,
                expires_at_micros: None,
            },
            CfgGetItem {
                key: "test2".to_string(),
                value: "2".to_string(),
                modified_at_micros: 20,
                expires_at_micros: Some(30),
            },
        ]);

        let bin: Vec<u8> = encode(&enc).unwrap();

        let res: CfgGetRes = decode(&bin).unwrap();

        assert_eq!(
            CfgGetItem {
                key: "test1".to_string(),
                value: "1".to_string(),
                modified_at_micros: 10,
                expires_at_micros: None,
            },
            res.as_ref().unwrap()[0],
        );
        assert_eq!(20, res.as_ref().unwrap()[1].modified_at_micros);
        assert_eq!(Some(30), res.as_ref().unwrap()[1].expires_at_micros);

        let enc2: CfgGetRes = Err("test-err".to_string());
        let bin2: Vec<u8> = encode(&enc2).unwrap();
        let res2: CfgGetRes = decode(&bin2).unwrap();
        assert_eq!("test-err", res2.unwrap_err());
    }
}
