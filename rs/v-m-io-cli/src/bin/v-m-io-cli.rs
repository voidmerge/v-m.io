use v_m_io_cli::{Config, client_run};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    use clap::Parser;

    let config = Config::parse();
    client_run(config).await
}
