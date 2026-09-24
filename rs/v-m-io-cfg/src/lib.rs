#![deny(missing_docs)]
//! v-m.io cfg

use std::io::Result;
use std::path::PathBuf;
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
    ///
    /// If not specified, defaults to `0.0.0.0:0`, or `127.0.0.1:44332` when
    /// `--test` is set.
    #[arg(
        long,
        env="V_M_IO_CFG_ADDR",
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
    ///
    /// If not provided, a random ephemeral key is generated. Data persisted
    /// under a random key is not readable after a restart.
    #[arg(long, env = "V_M_IO_CFG_ENCRYPTION_KEY")]
    pub encryption_key: Option<String>,

    /// Run in test mode.
    ///
    /// A temporary directory is used as the database root, the server binds
    /// `127.0.0.1:44332` (unless an explicit `--addr` is given), and a
    /// default `test` api key is seeded into the kv store. The temporary
    /// directory is removed, best effort, when the process exits.
    #[arg(long, env = "V_M_IO_CFG_TEST")]
    pub test: bool,
}

/// The db class under which all config entries are stored.
const CFG_CLASS: &str = "cfg";

/// Prefix marking a config entry as an api key rather than a regular config
/// value.
///
/// Api keys are initialized alongside regular config values, but are never
/// returned by the config getter.
const CFG_API_KEY_PREFIX: &str = "cfg-api-key~";

/// Prefix marking a config entry as an advertised local bind address.
const CFG_ADDR_PREFIX: &str = "cfg-addr~";

/// How often the locally bound addresses are (re)advertised.
const CFG_ADDR_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

/// How long an advertised bind address remains valid.
///
/// Twice the advertisement interval, so an entry stays valid across a single
/// missed refresh before the db prunes it.
const CFG_ADDR_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// Maximum size of a config value, imposed by the entry metadata column.
const CFG_VALUE_MAX: usize = 4096;

/// Maximum length of a config key, imposed by the db.
const CFG_KEY_MAX: usize = 1024;

/// The request name of the config getter, matching `ChanCliCfgExt::cfg_get`.
const CFG_GET_REQ: &str = "cfg-get";

/// The request name of the config setter, matching `ChanCliCfgExt::cfg_put`.
const CFG_PUT_REQ: &str = "cfg-put";

/// The default `--addr` value, used to detect whether the caller explicitly
/// supplied a bind address.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:0";

/// The bind address used in `--test` mode when no explicit `--addr` is given.
const TEST_BIND_ADDR: &str = "127.0.0.1:44332";

/// The api key seeded into the kv store in `--test` mode.
const TEST_API_KEY: &str = "test";

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

/// Encode raw key bytes as a standard base64 string.
fn encode_encryption_key(key: &[u8; 32]) -> String {
    use base64::Engine;

    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Generate a random 32 byte master key.
fn random_encryption_key() -> [u8; 32] {
    use rand::Rng;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Resolve the raw master key for `config`.
///
/// If no key was configured, a random ephemeral key is generated. Data
/// written under a random key cannot be read after a restart, so a stable
/// `--encryption-key` is required to persist data across runs.
fn resolve_encryption_key(config: &Config) -> Result<[u8; 32]> {
    match config.encryption_key.as_deref() {
        Some(key) if !key.is_empty() => parse_encryption_key(key),
        _ => {
            tracing::warn!(
                "no --encryption-key provided; generated a random ephemeral \
                 key (persisted data will not be readable on restart)",
            );
            Ok(random_encryption_key())
        }
    }
}

impl Config {
    /// Apply the `--test` convenience defaults in place.
    ///
    /// `root` becomes the database root, the default `test` api key is merged
    /// into the `init` values (seeding it on the next
    /// [`config_init`]/[`config_srv`] call), and the server binds
    /// `127.0.0.1:44332` unless an explicit `--addr` was supplied. If no
    /// encryption key is configured, a random one is pinned so that
    /// initialization and serving use the same key.
    ///
    /// The caller is responsible for removing `root` when done.
    pub fn apply_test_defaults(&mut self, root: PathBuf) -> Result<()> {
        self.db_root_dir = root.to_string_lossy().into_owned();

        // Only apply the test bind default when no `--addr` was supplied at
        // all. An explicit `--addr 0.0.0.0:0` is preserved, and `addr` is
        // also empty when `--addr` is passed with no values.
        if self.addr.is_empty() {
            self.addr =
                vec![TEST_BIND_ADDR.parse().expect("valid test bind address")];
        }

        let mut init: std::collections::BTreeMap<String, String> =
            match self.init.as_deref() {
                Some(init) => serde_json::from_str(init).map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid --init json: {err}"),
                    )
                })?,
                None => std::collections::BTreeMap::new(),
            };

        init.insert(
            format!("{CFG_API_KEY_PREFIX}{TEST_API_KEY}"),
            String::new(),
        );

        self.init = Some(serde_json::to_string(&init).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to encode init json: {err}"),
            )
        })?);

        // pin a single random key so initialization and serving agree when no
        // explicit key was provided
        if self
            .encryption_key
            .as_deref()
            .is_none_or(|key| key.is_empty())
        {
            self.encryption_key =
                Some(encode_encryption_key(&random_encryption_key()));
        }

        Ok(())
    }
}

/// Upsert a single config value, retrying on a timestamp collision.
async fn upsert_value(
    db: &VmIoDb,
    counter: &AtomicI64,
    key: String,
    value: String,
    expires_at_micros: Option<i64>,
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
                expires_at_micros,
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

/// Advertise each locally bound address as a `cfg-addr~<addr>` entry with an
/// empty value, expiring [`CFG_ADDR_TTL`] from now.
async fn announce_addrs(
    db: &VmIoDb,
    counter: &AtomicI64,
    addrs: &[std::net::SocketAddr],
) -> Result<()> {
    let expires_at_micros =
        unix_micros().saturating_add(CFG_ADDR_TTL.as_micros() as i64);

    for addr in addrs {
        upsert_value(
            db,
            counter,
            format!("{CFG_ADDR_PREFIX}{addr}"),
            String::new(),
            Some(expires_at_micros),
        )
        .await?;
    }

    Ok(())
}

/// Periodically (re)advertise the locally bound addresses.
///
/// Errors are logged and retried on the next pass rather than ending the task.
async fn announce_addrs_task(
    db: Arc<VmIoDb>,
    counter: Arc<AtomicI64>,
    addrs: Vec<std::net::SocketAddr>,
) {
    loop {
        if let Err(err) = announce_addrs(&db, &counter, &addrs).await {
            tracing::warn!("failed to advertise config server addrs: {err}");
        }

        tokio::time::sleep(CFG_ADDR_INTERVAL).await;
    }
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
            let CfgPutReq {
                key,
                value,
                expires_at_micros,
            } = decode(&req)?;

            // api keys may be pushed through the same interface as any other
            // config value
            upsert_value(
                &self.db,
                &self.counter,
                key,
                value,
                expires_at_micros,
            )
            .await?;

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
        resolve_encryption_key(config)?.into(),
    )
    .await?;

    let counter = AtomicI64::new(0);

    // init values never expire; expiries can only be set through `cfg-put`
    for (key, value) in values {
        upsert_value(&db, &counter, key, value, None).await?;
    }

    Ok(())
}

/// A running config server.
///
/// Dropping this aborts the address advertisement task in addition to the
/// underlying [ChanSrv]'s accept loops and in-flight connections.
pub struct CfgSrv {
    srv: ChanSrv,
    _tasks: tokio::task::JoinSet<()>,
}

impl std::ops::Deref for CfgSrv {
    type Target = ChanSrv;

    fn deref(&self) -> &Self::Target {
        &self.srv
    }
}

/// Open the config database and start the config server.
///
/// The returned [CfgSrv] keeps serving until it is dropped. While it runs, a
/// background task re-advertises each locally bound address as a
/// `cfg-addr~<addr>` entry every [`CFG_ADDR_INTERVAL`].
pub async fn config_srv(config: &Config) -> Result<CfgSrv> {
    let db = Arc::new(
        VmIoDb::new(
            config.db_root_dir.as_str(),
            resolve_encryption_key(config)?.into(),
        )
        .await?,
    );

    let counter = Arc::new(AtomicI64::new(0));

    let handlers: Vec<DynChanHandler> = vec![
        Arc::new(CfgGetHandler { db: db.clone() }),
        Arc::new(CfgPutHandler {
            db: db.clone(),
            counter: counter.clone(),
        }),
    ];

    let bind = if config.addr.is_empty() {
        // no `--addr` was supplied on the cli, fall back to the wildcard
        vec![
            DEFAULT_BIND_ADDR
                .parse()
                .expect("valid default bind address"),
        ]
    } else {
        config.addr.clone()
    };

    let srv = ChanSrv::new(ChanSrvConfig {
        auth_cb: make_auth_cb(db.clone()),
        handlers,
        bind,
    })
    .await?;

    let local_addrs = srv.local_addrs();

    for addr in &local_addrs {
        tracing::info!("config server listening on {addr}");
    }

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(announce_addrs_task(db, counter, local_addrs));

    Ok(CfgSrv { srv, _tasks: tasks })
}

/// Run the config server.
///
/// If `config.test` is set, the server runs in test mode: a temporary
/// directory is used as the database root, a default `test` api key is
/// seeded, and the server binds `127.0.0.1:44332` unless an explicit `--addr`
/// was given. The temporary directory is removed, best effort, when a
/// shutdown signal (ctrl-c or SIGTERM) is received.
///
/// Otherwise, if `config.init` is set, the database is initialized (or
/// overwritten) and the function returns without serving. Otherwise the
/// server runs until the process exits.
pub async fn config_run(config: Config) -> Result<()> {
    if config.test {
        return config_run_test(config).await;
    }

    if config.init.is_some() {
        return config_init(&config).await;
    }

    // keep the server alive for as long as this function runs
    let _srv = config_srv(&config).await?;

    std::future::pending::<()>().await;

    Ok(())
}

/// Run the config server in `--test` mode.
///
/// Uses a freshly created temporary directory as the database root, seeds a
/// default [`TEST_API_KEY`] api key, and serves until a shutdown signal is
/// received. The temporary directory is removed, best effort, before
/// returning.
async fn config_run_test(mut config: Config) -> Result<()> {
    let tmp = tempfile::tempdir()?;

    tracing::warn!(
        "--test mode: using temporary db root {}",
        tmp.path().display(),
    );

    config.apply_test_defaults(tmp.path().to_path_buf())?;

    // initialize (or overwrite) the database, seeding the test api key
    config_init(&config).await?;

    // now serve from the initialized database
    config.init = None;
    let srv = config_srv(&config).await?;

    for addr in srv.local_addrs() {
        tracing::warn!(
            "--test mode: listening on {addr} (api key: \"{TEST_API_KEY}\")",
        );
    }

    // wait for a graceful shutdown so we can clean up the temp dir
    wait_for_shutdown().await;

    // drop the server (closing the db) before removing the directory
    drop(srv);
    drop(tmp);

    Ok(())
}

/// Resolve once the process receives a shutdown signal.
///
/// Listens for ctrl-c, and additionally SIGTERM on unix.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!("failed to install SIGTERM handler: {err}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn announce_addrs_writes_empty_value_with_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let db = VmIoDb::new(dir.path(), [0x42; 32].into()).await.unwrap();
        let counter = AtomicI64::new(0);

        let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let before = unix_micros();

        announce_addrs(&db, &counter, &[addr]).await.unwrap();

        let after = unix_micros();

        let entry = db
            .get(CFG_CLASS.to_string(), format!("{CFG_ADDR_PREFIX}{addr}"))
            .await
            .unwrap()
            .unwrap();

        // empty value
        assert_eq!(Some(Vec::<u8>::new()), entry.metadata);

        // expires one TTL from the time it was written
        let ttl = CFG_ADDR_TTL.as_micros() as i64;
        let expires = entry.expires_at_micros.unwrap();
        assert!(expires >= before + ttl);
        assert!(expires <= after + ttl);
    }
}
