use tracing_subscriber::EnvFilter;
use v_m_io_cfg::{Config, config_run};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    use clap::Parser;

    // honor RUST_LOG when set, otherwise default to INFO
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(std::io::Error::other)?;

    let config = Config::parse();
    config_run(config).await
}
