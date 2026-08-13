//! API types.

use serde::{Deserialize, Serialize};
use std::io::Result;

const CONFIG: bincode_next::config::Configuration =
    bincode_next::config::standard();

// ## WARNING - CRITICAL ##
//
// We're using bincode here, which doesn't use tags...
// - you can only add #[serde(default)] fields to the end of enum variants
// - you cannot re-order variant fields or variants themselves
// - only add new variants to the end

/// Main API codec enum.
#[derive(Debug, Serialize, Deserialize)]
pub enum Api {
    /// We were unable to parse the request or response.
    Unknown,

    /// Make a rate-limit query.
    RateRequest {
        /// The organization identifier for the rate-limiter.
        org_id: String,

        /// If this organization has more than this count of instances,
        /// the request will fail.
        max_inst: u64,

        /// The instance identifier for the rate-limiter.
        /// (concat whatever you want into this, e.g. type+ip address, etc).
        inst_id: String,

        /// The weight in seconds of this trigger (can be zero to just query).
        weight_secs: f64,
    },

    /// Response to a rate-limit query.
    RateResponse {
        /// The "now" timestamp in seconds as known by the server
        /// at time of rate-limit evaluation.
        now: f64,

        /// The "cur" timestamp post-processing. This will be >= now.
        cur: f64,
    },
}

impl Api {
    /// Encode to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode_next::serde::encode_to_vec(self, CONFIG)
            .map_err(std::io::Error::other)
    }

    /// Decode from bytes.
    pub fn decode(slice: &[u8]) -> Result<Self> {
        if let Ok((out, _)) =
            bincode_next::serde::decode_from_slice(slice, CONFIG)
        {
            Ok(out)
        } else {
            Ok(Self::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let enc = Api::RateResponse {
            now: 3.14159,
            cur: 42.0,
        }
        .encode()
        .unwrap();

        println!("{:?}", Api::decode(&enc));
    }
}
