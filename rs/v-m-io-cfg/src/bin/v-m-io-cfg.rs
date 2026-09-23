use v_m_io_cfg::{Config, config_run};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    use clap::Parser;

    let config = Config::parse();
    config_run(config).await
}
