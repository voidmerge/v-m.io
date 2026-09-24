//! Integration tests for the config server, driven through the
//! [ChanCliCfgExt] extension trait.

use std::net::SocketAddr;
use std::path::Path;

use base64::Engine;
use v_m_io_cfg::{Config, config_init, config_srv};
use v_m_io_chan::cfg::ChanCliCfgExt;
use v_m_io_chan::{ChanCli, ChanSrv};

/// The api key used to authorize the tests' config client.
const API_KEY: &str = "test-api-key-1234";

/// A valid base64-encoded 32 byte master key.
fn b64_key() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

/// Build a config pointing at `dir`.
fn config(dir: &Path, init: Option<String>) -> Config {
    Config {
        db_root_dir: dir.to_string_lossy().into_owned(),
        addr: vec!["127.0.0.1:0".parse().unwrap()],
        init,
        encryption_key: b64_key(),
    }
}

/// An init json object that seeds the tests' api key.
fn api_key_init() -> String {
    serde_json::json!({ format!("cfg-api-key~{API_KEY}"): "" }).to_string()
}

/// Initialize the db at `dir` with the tests' api key.
async fn init_api_key(dir: &Path) {
    let cfg = config(dir, Some(api_key_init()));
    config_init(&cfg).await.unwrap();
}

/// Start a config server on an ephemeral port.
async fn start(dir: &Path) -> (ChanSrv, SocketAddr) {
    let cfg = config(dir, None);
    let srv = config_srv(&cfg).await.unwrap();
    let addr = srv.local_addrs()[0];
    (srv, addr)
}

/// Connect an authorized config client.
async fn client(addr: SocketAddr) -> ChanCli {
    ChanCli::connect(addr, format!("Bearer {API_KEY}"))
        .await
        .unwrap()
}

/// The `(key, value)` entry under which the tests' seeded api key is stored.
fn api_key_entry() -> (String, String) {
    (format!("cfg-api-key~{API_KEY}"), String::new())
}

#[tokio::test]
async fn put_get_roundtrip_and_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    assert_eq!(
        vec![api_key_entry()],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );

    cli.cfg_put(("alpha".into(), "one".into())).await.unwrap();
    cli.cfg_put(("beta".into(), "two".into())).await.unwrap();

    assert_eq!(
        vec![
            ("alpha".to_string(), "one".to_string()),
            ("beta".to_string(), "two".to_string()),
            api_key_entry(),
        ],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );

    cli.cfg_put(("alpha".into(), "updated".into()))
        .await
        .unwrap();

    assert_eq!(
        vec![
            ("alpha".to_string(), "updated".to_string()),
            ("beta".to_string(), "two".to_string()),
            api_key_entry(),
        ],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn empty_and_unicode_values_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    cli.cfg_put(("empty".into(), "".into())).await.unwrap();
    cli.cfg_put(("unicode".into(), "héllo → 世界".into()))
        .await
        .unwrap();

    assert_eq!(
        vec![
            api_key_entry(),
            ("empty".to_string(), "".to_string()),
            ("unicode".to_string(), "héllo → 世界".to_string()),
        ],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn api_keys_are_returned() {
    let dir = tempfile::tempdir().unwrap();

    let init = serde_json::json!({
        format!("cfg-api-key~{API_KEY}"): "",
        "public": "value",
    })
    .to_string();

    let cfg = config(dir.path(), Some(init));
    config_init(&cfg).await.unwrap();

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    assert_eq!(
        vec![api_key_entry(), ("public".to_string(), "value".to_string())],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn unknown_api_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;

    // connect() runs the health check, which is itself subject to auth
    assert!(
        ChanCli::connect(addr, "Bearer not-a-real-key".to_string())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pushed_api_key_can_authenticate() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    cli.cfg_put(("cfg-api-key~second".into(), "".into()))
        .await
        .unwrap();

    let cli2 = ChanCli::connect(addr, "Bearer second".to_string())
        .await
        .unwrap();

    // the newly pushed api key is exposed by the getter alongside the seeded
    // one, both with empty values
    assert_eq!(
        vec![
            ("cfg-api-key~second".to_string(), String::new()),
            api_key_entry(),
        ],
        cli2.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn values_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    {
        let (srv, addr) = start(dir.path()).await;
        let cli = client(addr).await;
        cli.cfg_put(("persisted".into(), "yes".into()))
            .await
            .unwrap();

        drop(srv);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    assert_eq!(
        vec![api_key_entry(), ("persisted".to_string(), "yes".to_string())],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn init_overwrites_existing_values() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    {
        let (srv, addr) = start(dir.path()).await;
        let cli = client(addr).await;
        cli.cfg_put(("k".into(), "old".into())).await.unwrap();

        drop(srv);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let init = serde_json::json!({
        format!("cfg-api-key~{API_KEY}"): "",
        "k": "new",
    })
    .to_string();

    let cfg = config(dir.path(), Some(init));
    config_init(&cfg).await.unwrap();

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    assert_eq!(
        vec![api_key_entry(), ("k".to_string(), "new".to_string())],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn oversized_value_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;
    let cli = client(addr).await;

    let big = "x".repeat(4097);

    assert!(cli.cfg_put(("big".into(), big)).await.is_err());

    // the rejected write must not have landed
    assert_eq!(
        vec![api_key_entry()],
        cli.cfg_get(()).await.unwrap().unwrap(),
    );
}

#[tokio::test]
async fn server_requires_auth() {
    let dir = tempfile::tempdir().unwrap();
    init_api_key(dir.path()).await;

    let (_srv, addr) = start(dir.path()).await;

    // a client that sends no Authorization header is rejected by the channel
    // layer before the auth callback runs
    let res = reqwest::Client::new()
        .post(format!("http://{addr}/cfg-get"))
        .body(Vec::new())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}
