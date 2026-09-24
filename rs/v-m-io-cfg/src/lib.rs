#![deny(missing_docs)]
//! v-m.io cfg

use std::io::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use v_m_io_chan::{
    BoxFut, ChanHandler, ChanSrv, ChanSrvConfig, DynAuthCb, DynChanHandler,
};
use v_m_io_db::{VmIoDb, VmIoDbListFilter, VmIoDbListSort};
use v_m_io_types::api::{CfgGetRes, CfgPutReq, decode, encode};

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

/// The db class under which all config entries are stored.
const CFG_CLASS: &str = "cfg";

/// Prefix marking a config entry as an api key rather than a regular config
/// value.
///
/// Api keys are initialized alongside regular config values, but are never
/// returned by the config getter.
const CFG_API_KEY_PREFIX: &str = "cfg-api-key~";

/// Maximum size of a config value, imposed by the entry metadata column.
const CFG_VALUE_MAX: usize = 4096;

/// Maximum length of a config key, imposed by the db.
const CFG_KEY_MAX: usize = 1024;

/// The request name of the config getter, matching `ChanCliCfgExt::cfg_get`.
const CFG_GET_REQ: &str = "cfg-get";

/// The request name of the config setter, matching `ChanCliCfgExt::cfg_put`.
const CFG_PUT_REQ: &str = "cfg-put";

/// Current unix epoch timestamp in microseconds.
fn unix_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_micros() as i64)
        .unwrap_or(0)
}

/// Allocate a strictly increasing microsecond timestamp.
///
/// The db requires `modified_at_micros` to be unique across all entries, but
/// a burst of writes can easily land within the same microsecond. The shared
/// counter bumps past any timestamp already handed out.
fn next_micros(counter: &AtomicI64) -> i64 {
    let now = unix_micros();
    loop {
        let prev = counter.load(Ordering::SeqCst);
        let next = if prev >= now { prev + 1 } else { now };
        if counter
            .compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return next;
        }
    }
}

/// Decode the base64 master key into the raw 32 bytes the db expects.
fn parse_encryption_key(key: &str) -> Result<[u8; 32]> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("encryption key is not valid base64: {err}"),
            )
        })?;

    bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "encryption key must decode to exactly 32 bytes",
        )
    })
}

/// Upsert a single config value, retrying on a timestamp collision.
async fn upsert_value(
    db: &VmIoDb,
    counter: &AtomicI64,
    key: String,
    value: String,
) -> Result<()> {
    if key.len() > CFG_KEY_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config key cannot be > 1024 bytes",
        ));
    }

    let metadata = value.into_bytes();

    if metadata.len() > CFG_VALUE_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config value cannot be > 4096 bytes",
        ));
    }

    let mut last_err = None;

    // the only expected failure is the unique modified_at_micros constraint,
    // which the strictly increasing counter resolves on the next attempt
    for _ in 0..64 {
        let modified_at_micros = next_micros(counter);
        match db
            .upsert(
                CFG_CLASS.to_string(),
                key.clone(),
                modified_at_micros,
                None,
                Some(metadata.clone()),
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to allocate a unique timestamp")
    }))
}

/// Read every regular config value, excluding api keys.
///
/// Values are returned sorted by key ascending.
async fn read_all(db: &VmIoDb) -> Result<Vec<(String, String)>> {
    let entries = db
        .list(
            CFG_CLASS.to_string(),
            VmIoDbListFilter::All,
            VmIoDbListSort::KeyAsc,
            i64::MAX,
        )
        .await?;

    let mut out = Vec::with_capacity(entries.len());

    for entry in entries {
        let value = match entry.metadata {
            Some(metadata) => String::from_utf8(metadata).map_err(|_| {
                std::io::Error::other("config value is not valid utf-8")
            })?,
            None => String::new(),
        };

        out.push((entry.key, value));
    }

    Ok(out)
}

/// Handler for the `cfg-get` request.
struct CfgGetHandler {
    db: Arc<VmIoDb>,
}

impl ChanHandler for CfgGetHandler {
    fn req(&self) -> &'static str {
        CFG_GET_REQ
    }

    fn handle(&self, _req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            let res: CfgGetRes = match read_all(&self.db).await {
                Ok(values) => Ok(values),
                Err(err) => Err(err.to_string()),
            };

            encode(&res)
        })
    }
}

/// Handler for the `cfg-put` request.
struct CfgPutHandler {
    db: Arc<VmIoDb>,
    counter: Arc<AtomicI64>,
}

impl ChanHandler for CfgPutHandler {
    fn req(&self) -> &'static str {
        CFG_PUT_REQ
    }

    fn handle(&self, req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            let (key, value): CfgPutReq = decode(&req)?;

            // api keys may be pushed through the same interface as any other
            // config value
            upsert_value(&self.db, &self.counter, key, value).await?;

            // CfgPutRes is the unit type: an empty response body
            Ok(Vec::new())
        })
    }
}

/// Build the authorization callback.
///
/// The presented bearer token is authorized if the db holds a
/// `cfg-api-key~<token>` entry.
fn make_auth_cb(db: Arc<VmIoDb>) -> DynAuthCb {
    Arc::new(move |auth: String| {
        let db = db.clone();

        Box::pin(async move {
            let token =
                auth.strip_prefix("Bearer ").unwrap_or(auth.as_str()).trim();

            if token.is_empty() {
                tracing::warn!("authentication failed: missing bearer token");
                return Ok(hyper::StatusCode::UNAUTHORIZED);
            }

            let key = format!("{CFG_API_KEY_PREFIX}{token}");

            match db.get(CFG_CLASS.to_string(), key).await {
                Ok(Some(_)) => Ok(hyper::StatusCode::OK),
                Ok(None) => {
                    tracing::warn!("authentication failed: unknown api key");
                    Ok(hyper::StatusCode::UNAUTHORIZED)
                }
                Err(err) => {
                    tracing::warn!(
                        "authentication error: api key lookup failed: {err}"
                    );
                    Ok(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        })
    })
}

/// Initialize (or overwrite) the config database with the values from the
/// `init` json object, then return.
///
/// Entries whose key starts with [`CFG_API_KEY_PREFIX`] are stored as api
/// keys and used to authorize subsequent server requests.
pub async fn config_init(config: &Config) -> Result<()> {
    let init = config.init.as_deref().unwrap_or("{}");

    let values: std::collections::BTreeMap<String, String> =
        serde_json::from_str(init).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid --init json: {err}"),
            )
        })?;

    let db = VmIoDb::new(
        config.db_root_dir.as_str(),
        parse_encryption_key(&config.encryption_key)?.into(),
    )
    .await?;

    let counter = AtomicI64::new(0);

    for (key, value) in values {
        upsert_value(&db, &counter, key, value).await?;
    }

    Ok(())
}

/// Open the config database and start the config server.
///
/// The returned [ChanSrv] keeps serving until it is dropped.
pub async fn config_srv(config: &Config) -> Result<ChanSrv> {
    let db = Arc::new(
        VmIoDb::new(
            config.db_root_dir.as_str(),
            parse_encryption_key(&config.encryption_key)?.into(),
        )
        .await?,
    );

    let counter = Arc::new(AtomicI64::new(0));

    let handlers: Vec<DynChanHandler> = vec![
        Arc::new(CfgGetHandler { db: db.clone() }),
        Arc::new(CfgPutHandler {
            db: db.clone(),
            counter,
        }),
    ];

    let srv = ChanSrv::new(ChanSrvConfig {
        auth_cb: make_auth_cb(db),
        handlers,
        bind: config.addr.clone(),
    })
    .await?;

    for addr in srv.local_addrs() {
        tracing::info!("config server listening on {addr}");
    }

    Ok(srv)
}

/// Run the config server.
///
/// If `config.init` is set, the database is initialized (or overwritten) and
/// the function returns without serving. Otherwise the server runs until the
/// process exits.
pub async fn config_run(config: Config) -> Result<()> {
    if config.init.is_some() {
        return config_init(&config).await;
    }

    // keep the server alive for as long as this function runs
    let _srv = config_srv(&config).await?;

    std::future::pending::<()>().await;

    Ok(())
}
