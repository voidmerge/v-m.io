#![deny(missing_docs)]
//! v-m.io cli

use std::io::Result;

use v_m_io_chan::ChanCli;
use v_m_io_chan::cfg::ChanCliCfgExt;

/// Configure how to invoke the v-m.io client.
#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct Config {
    /// V-m.io server address.
    #[arg(long, env = "V_M_IO_ADDR")]
    pub addr: std::net::SocketAddr,

    /// Api token allowing access.
    #[arg(long, env = "V_M_IO_API_KEY")]
    pub api_key: String,

    #[command(subcommand)]
    cmd: Cmd,
}

/// Client subcommands.
#[derive(Clone, Debug, clap::Parser)]
enum Cmd {
    /// Authentication + Health check of v-m.io server.
    Health,

    /// Dump the full config.
    CfgGet,

    /// Write an entry to the config.
    CfgPut {
        /// The config entry key.
        key: String,
        /// The config entry value.
        value: String,
    },
}

/// Execute the specified client subcommand.
pub async fn client_run(config: Config) -> Result<()> {
    let cmd = config.cmd.clone();
    match cmd {
        Cmd::Health => health(config).await,
        Cmd::CfgGet => {
            let cfg = cfg_get(config).await?.map_err(std::io::Error::other)?;
            println!("{cfg:#?}");
            Ok(())
        }
        Cmd::CfgPut { key, value } => cfg_put(config, key, value).await,
    }
}

/// Authentication + Health check of v-m.io server.
pub async fn health(config: Config) -> Result<()> {
    let cli =
        ChanCli::connect(config.addr, format!("Bearer {}", config.api_key))
            .await?;
    cli.request("__health", vec![]).await?;
    Ok(())
}

/// Dump the full config.
pub async fn cfg_get(config: Config) -> Result<v_m_io_types::api::CfgGetRes> {
    let cli =
        ChanCli::connect(config.addr, format!("Bearer {}", config.api_key))
            .await?;
    cli.cfg_get(()).await
}

/// Write an entry to the config.
pub async fn cfg_put(config: Config, key: String, value: String) -> Result<()> {
    let cli =
        ChanCli::connect(config.addr, format!("Bearer {}", config.api_key))
            .await?;
    cli.cfg_put((key, value)).await
}
