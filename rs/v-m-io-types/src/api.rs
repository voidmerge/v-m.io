//! API types.

const CONFIG: bincode_next::config::Configuration =
    bincode_next::config::standard();

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

/// `cfg-get` response payload.
pub type CfgGetRes = Result<Vec<(String, String)>, String>;

/// `cfg-put` request payload.
pub type CfgPutReq = (String, String);

/// `cfg-put` response payload.
pub type CfgPutRes = ();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let enc: CfgGetRes = Ok(vec![
            ("test1".to_string(), "1".to_string()),
            ("test2".to_string(), "2".to_string()),
        ]);

        let bin: Vec<u8> = encode(&enc).unwrap();

        let res: CfgGetRes = decode(&bin).unwrap();

        assert_eq!("test1", res.as_ref().unwrap()[0].0);
        assert_eq!("2", res.as_ref().unwrap()[1].1);

        let enc2: CfgGetRes = Err("test-err".to_string());
        let bin2: Vec<u8> = encode(&enc2).unwrap();
        let res2: CfgGetRes = decode(&bin2).unwrap();
        assert_eq!("test-err", res2.unwrap_err());
    }
}
