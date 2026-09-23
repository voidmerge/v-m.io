//! Config-related apis.

use crate::*;
use v_m_io_types::api::*;

/// Helper extension trait to include cfg requests to channel client.
pub trait ChanCliCfgExt {
    /// Get the current complete config.
    fn cfg_get(&self, input: CfgGetReq) -> BoxFut<'_, Result<CfgGetRes>>;

    /// Push a new config value.
    fn cfg_put(&self, input: CfgPutReq) -> BoxFut<'_, Result<CfgPutRes>>;
}

impl ChanCliCfgExt for ChanCli {
    fn cfg_get(&self, _input: CfgGetReq) -> BoxFut<'_, Result<CfgGetRes>> {
        Box::pin(async move {
            let payload = self.request("cfg-get", vec![]).await?;
            decode(&payload)
        })
    }

    fn cfg_put(&self, input: CfgPutReq) -> BoxFut<'_, Result<CfgPutRes>> {
        Box::pin(async move {
            let payload = self.request("cfg-put", encode(&input)?).await?;
            if !payload.is_empty() {
                Err(std::io::Error::other("unexpected cfg_put result"))
            } else {
                Ok(())
            }
        })
    }
}
