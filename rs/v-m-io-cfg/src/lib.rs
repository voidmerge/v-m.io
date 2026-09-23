#![deny(missing_docs)]
//! v-m.io cfg

/// Configure how to run the config server.
#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub struct Config {
    /// Select the root directory where data should be persisted.
    #[arg(long, env = "V_M_IO_CFG_DB_ROOT_DIR", default_value = ".")]
    pub db_root_dir: String,

    /// Comma-separated list of local addresses to which we should bind the
    /// server.
    #[arg(
        long,
        env="V_M_IO_CFG_ADDR",
        default_value="0.0.0.0:0",
        value_delimiter=',',
        num_args=0..
    )]
    pub addr: Vec<std::net::SocketAddr>,

    /// A `{ [key: string]: string }` json object of config values with which
    /// to initialize the server. If this is set, the server will initialize
    /// (or overwrite) the database with these values, then exit. Run the
    /// server again without this setting to actually run the server.
    #[arg(long, env = "V_M_IO_CFG_INIT")]
    pub init: Option<String>,

    /// Base64 Encryption key (32 bytes) for at-rest db encryption.
    #[arg(long, env = "V_M_IO_CFG_ENCRYPTION_KEY")]
    pub encryption_key: String,
}

/// Run the config server.
pub async fn config_run(config: Config) -> std::io::Result<()> {
    println!("#CFG#{config:?}");

    todo!()
}
