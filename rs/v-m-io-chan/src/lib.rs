#![deny(missing_docs)]
//! v-m.io chan

use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::TcpListenerStream;

/// Boxed Future.
pub type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a + Send>>;

/// Describes a v-m.io channel handler.
pub trait ChanHandler {
    /// The request name this handler handles.
    fn req(&self) -> &'static str;

    /// Handle an incoming request.
    fn handle(&self, req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>>;
}

/// Dyn Trait-object [ChanHandler].
pub type DynChanHandler = Arc<dyn ChanHandler + 'static + Send + Sync>;

/// Authorization header value.
pub type AuthHeaderVal = String;

/// Authorization callback.
///
/// If this callback returns Ok(200) the call is authorized.
/// If this callback returns Ok(_) any other code, that status code will
/// be returned, with the canonical_reason of that code for the body.
/// If this callback returns Err(_), a 500 will be returned with a stringified
/// error response.
pub type DynAuthCb = Arc<
    dyn Fn(AuthHeaderVal) -> BoxFut<'static, Result<hyper::StatusCode>>
        + 'static
        + Send
        + Sync,
>;

/// Implicit health-check request name.
const HEALTH_REQ: &str = "__health";

/// Maximum accepted request body size.
const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB

/// Maximum number of simultaneous connections.
const MAX_CONNS: usize = 2048;

/// How long an incoming connection will wait for a concurrency permit.
const CONN_WAIT: std::time::Duration = std::time::Duration::from_millis(17);

/// Shared state handed to every spawned connection task.
struct SrvInner {
    auth_cb: DynAuthCb,
    handlers: HashMap<&'static str, DynChanHandler>,
}

/// Implicit handler used for connection health checks.
///
/// It succeeds with an empty body when the request body is empty, and errors
/// otherwise.
struct HealthHandler;

impl ChanHandler for HealthHandler {
    fn req(&self) -> &'static str {
        HEALTH_REQ
    }

    fn handle(&self, req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            if req.is_empty() {
                Ok(Vec::new())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "health check does not accept a body",
                ))
            }
        })
    }
}

/// Build a plain response with the given status code and body.
fn resp(code: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body.into()));
    *res.status_mut() = code;
    res
}

/// Build a plain-text error response.
fn resp_text(
    code: StatusCode,
    body: impl Into<Bytes>,
) -> Response<Full<Bytes>> {
    let mut res = resp(code, body);
    res.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// Handle a single incoming request.
async fn handle_request(
    inner: Arc<SrvInner>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    // -- authorization ----------------------------------------------------
    //
    // A missing (or non-ascii) Authorization header is rejected up front,
    // the auth callback is not consulted. Otherwise the callback receives
    // the full header value, including any "Bearer " prefix.
    let auth_val = match req.headers().get(AUTHORIZATION) {
        Some(val) => match val.to_str() {
            Ok(val) => val.to_string(),
            Err(_) => {
                return Ok(resp_text(
                    StatusCode::UNAUTHORIZED,
                    "missing or invalid authorization",
                ));
            }
        },
        None => {
            return Ok(resp_text(
                StatusCode::UNAUTHORIZED,
                "missing or invalid authorization",
            ));
        }
    };

    match (inner.auth_cb)(auth_val).await {
        Ok(code) if code == StatusCode::OK => {}
        Ok(code) => {
            let body = code.canonical_reason().unwrap_or("").to_string();
            return Ok(resp_text(code, body));
        }
        Err(err) => {
            return Ok(resp_text(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            ));
        }
    }

    // -- routing ----------------------------------------------------------
    //
    // Exactly one non-empty path segment selects the handler.
    let name = match req.uri().path() {
        "/" => None,
        path => {
            let name = path.strip_prefix('/').unwrap_or(path);
            if name.is_empty() || name.contains('/') {
                None
            } else {
                Some(name)
            }
        }
    };

    let handler = match name.and_then(|name| inner.handlers.get(name)) {
        Some(handler) => handler.clone(),
        None => {
            return Ok(resp_text(StatusCode::NOT_FOUND, "not found"));
        }
    };

    // -- body -------------------------------------------------------------
    if let Some(len) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|val| val.parse::<u64>().ok())
        && len > MAX_BODY as u64
    {
        return Ok(resp_text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload exceeds maximum size limit",
        ));
    }

    let limited = Limited::new(req.into_body(), MAX_BODY);
    let body = match limited.collect().await {
        Ok(body) => body.to_bytes(),
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(resp_text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload exceeds maximum size limit",
                ));
            }

            return Ok(resp_text(
                StatusCode::BAD_REQUEST,
                "failed to read stream or malformed payload",
            ));
        }
    };

    // -- dispatch ---------------------------------------------------------
    match handler.handle(body.to_vec()).await {
        Ok(out) => Ok(resp(StatusCode::OK, out)),
        Err(err) => Ok(resp_text(
            StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        )),
    }
}

/// Serve a single accepted connection.
async fn serve_connection(
    io: TokioIo<tokio::net::TcpStream>,
    inner: Arc<SrvInner>,
    sem: Arc<Semaphore>,
) {
    let _permit =
        match tokio::time::timeout(CONN_WAIT, sem.acquire_owned()).await {
            Err(_) => {
                let builder = auto::Builder::new(TokioExecutor::new());

                let _ = builder
                    .serve_connection(
                        io,
                        service_fn(|_: Request<Incoming>| async {
                            let mut res = resp_text(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Service Unavailable",
                            );
                            res.headers_mut().insert(
                                RETRY_AFTER,
                                hyper::header::HeaderValue::from_static("60"),
                            );
                            Ok::<_, std::convert::Infallible>(res)
                        }),
                    )
                    .await;
                return;
            }
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return,
        };

    let builder = auto::Builder::new(TokioExecutor::new());

    let service = service_fn(move |req: Request<Incoming>| {
        let inner = inner.clone();
        async move { handle_request(inner, req).await }
    });

    if let Err(err) = builder.serve_connection(io, service).await {
        eprintln!("Error serving connection: {:?}", err);
    }
}

/// Accept connections forever, spawning a task per connection.
async fn accept_loop(
    listener: TcpListener,
    inner: Arc<SrvInner>,
    sem: Arc<Semaphore>,
) {
    let mut stream = TcpListenerStream::new(listener);

    while let Some(conn) = stream.next().await {
        let stream = match conn {
            Ok(stream) => stream,
            Err(_) => continue,
        };

        let io = TokioIo::new(stream);
        let inner = inner.clone();
        let sem = sem.clone();

        tokio::task::spawn(async move {
            serve_connection(io, inner, sem).await;
        });
    }
}

/// Configuration for a chan server.
pub struct ChanSrvConfig {
    /// Authorization callback.
    pub auth_cb: DynAuthCb,

    /// List of handlers. [ChanHandler::req] must be unique for each entry.
    pub handlers: Vec<DynChanHandler>,

    /// List of local addrs to bind.
    pub bind: Vec<std::net::SocketAddr>,
}

/// v-m.io channel server
pub struct ChanSrv {
    local_addrs: Vec<std::net::SocketAddr>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ChanSrv {
    /// Construct a new channel server instance, and start listening for
    /// and handling incoming requests.
    pub async fn new(config: ChanSrvConfig) -> Result<Self> {
        let mut handlers = HashMap::new();

        let health: DynChanHandler = Arc::new(HealthHandler);
        handlers.insert(HEALTH_REQ, health);

        for handler in config.handlers {
            let name = handler.req();
            if handlers.insert(name, handler).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("duplicate handler req: {name}"),
                ));
            }
        }

        let inner = Arc::new(SrvInner {
            auth_cb: config.auth_cb,
            handlers,
        });

        let listeners = futures_util::future::try_join_all(
            config.bind.into_iter().map(TcpListener::bind),
        )
        .await?;

        let local_addrs = listeners
            .iter()
            .map(|listener| listener.local_addr())
            .collect::<Result<Vec<_>>>()?;

        let sem = Arc::new(Semaphore::new(MAX_CONNS));
        let mut tasks = Vec::with_capacity(listeners.len());

        for listener in listeners {
            let inner = inner.clone();
            let sem = sem.clone();
            tasks.push(tokio::task::spawn(accept_loop(listener, inner, sem)));
        }

        Ok(Self {
            local_addrs,
            _tasks: tasks,
        })
    }

    /// Get the local socket addresses this server is listening on.
    pub fn local_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.local_addrs.clone()
    }
}

/// v-m.io channel client
pub struct ChanCli {
    client: reqwest::Client,
    base: String,
    auth_header: AuthHeaderVal,
}

impl ChanCli {
    /// Connect to a remote chan server.
    pub async fn connect(
        addr: std::net::SocketAddr,
        auth_header: AuthHeaderVal,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(64)
            .build()
            .map_err(std::io::Error::other)?;

        let cli = Self {
            client,
            base: format!("http://{addr}"),
            auth_header,
        };

        // Verify the remote is reachable with the implicit health check.
        cli.request(HEALTH_REQ, Vec::new()).await?;

        Ok(cli)
    }

    /// Make a request of the connected channel server.
    pub async fn request(&self, req: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        if req.is_empty() || req.contains('/') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "req must be a single non-empty path segment",
            ));
        }

        let url = format!("{}/{}", self.base, req);

        let res = self
            .client
            .post(&url)
            .header(AUTHORIZATION, self.auth_header.as_str())
            .body(body)
            .send()
            .await
            .map_err(std::io::Error::other)?;

        let status = res.status();
        let bytes = res.bytes().await.map_err(std::io::Error::other)?;

        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(std::io::Error::other(format!(
                "request failed: {} {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Echo;

    impl ChanHandler for Echo {
        fn req(&self) -> &'static str {
            "echo"
        }

        fn handle(&self, req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
            Box::pin(async move { Ok(req) })
        }
    }

    struct Fail;

    impl ChanHandler for Fail {
        fn req(&self) -> &'static str {
            "fail"
        }

        fn handle(&self, _req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
            Box::pin(async move { Err(std::io::Error::other("boom")) })
        }
    }

    struct Counted {
        count: Arc<AtomicUsize>,
    }

    impl ChanHandler for Counted {
        fn req(&self) -> &'static str {
            "count"
        }

        fn handle(&self, _req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
            let count = self.count.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(b"ok".to_vec())
            })
        }
    }

    fn handler<T: ChanHandler + Send + Sync + 'static>(
        handler: T,
    ) -> DynChanHandler {
        Arc::new(handler)
    }

    fn auth_eq(expected: &'static str) -> DynAuthCb {
        Arc::new(move |val: AuthHeaderVal| {
            Box::pin(async move {
                if val == expected {
                    Ok(StatusCode::OK)
                } else {
                    Ok(StatusCode::UNAUTHORIZED)
                }
            })
        })
    }

    fn auth_code(code: StatusCode) -> DynAuthCb {
        Arc::new(move |_val: AuthHeaderVal| Box::pin(async move { Ok(code) }))
    }

    async fn start(
        handlers: Vec<DynChanHandler>,
        auth_cb: DynAuthCb,
    ) -> (ChanSrv, SocketAddr) {
        let config = ChanSrvConfig {
            auth_cb,
            handlers,
            bind: vec!["127.0.0.1:0".parse().unwrap()],
        };

        let srv = ChanSrv::new(config).await.unwrap();
        let addr = srv.local_addrs()[0];
        (srv, addr)
    }

    #[tokio::test]
    async fn echo_roundtrip() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_eq("Bearer test")).await;

        let cli = ChanCli::connect(addr, "Bearer test".to_string())
            .await
            .unwrap();

        let out = cli.request("echo", b"hello".to_vec()).await.unwrap();
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn unknown_handler_is_err() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_eq("Bearer test")).await;

        let cli = ChanCli::connect(addr, "Bearer test".to_string())
            .await
            .unwrap();

        assert!(cli.request("nope", b"x".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn wrong_auth_is_rejected_and_handler_skipped() {
        let count = Arc::new(AtomicUsize::new(0));

        let (_srv, addr) = start(
            vec![handler(Counted {
                count: count.clone(),
            })],
            auth_eq("Bearer test"),
        )
        .await;

        // The connect-time health check is also subject to auth.
        assert!(
            ChanCli::connect(addr, "Bearer wrong".to_string())
                .await
                .is_err()
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn auth_callback_other_code_is_err() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_code(StatusCode::IM_A_TEAPOT))
                .await;

        // Bypass ChanCli, since connect would itself fail this auth check.
        let res = reqwest::Client::new()
            .post(format!("http://{addr}/echo"))
            .header(AUTHORIZATION, "Bearer test")
            .body(b"x".to_vec())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn health_check_is_ok() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_eq("Bearer test")).await;

        // connect() runs the health check, so this already proves it works.
        let cli = ChanCli::connect(addr, "Bearer test".to_string())
            .await
            .unwrap();

        let out = cli.request(HEALTH_REQ, Vec::new()).await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn health_check_rejects_body() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_eq("Bearer test")).await;

        let cli = ChanCli::connect(addr, "Bearer test".to_string())
            .await
            .unwrap();

        assert!(cli.request(HEALTH_REQ, b"x".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn duplicate_health_handler_is_err() {
        struct SneakyHealth;

        impl ChanHandler for SneakyHealth {
            fn req(&self) -> &'static str {
                HEALTH_REQ
            }

            fn handle(&self, _req: Vec<u8>) -> BoxFut<'_, Result<Vec<u8>>> {
                Box::pin(async move { Ok(Vec::new()) })
            }
        }

        let config = ChanSrvConfig {
            auth_cb: auth_eq("Bearer test"),
            handlers: vec![handler(SneakyHealth)],
            bind: vec!["127.0.0.1:0".parse().unwrap()],
        };

        assert!(ChanSrv::new(config).await.is_err());
    }

    #[tokio::test]
    async fn handler_error_is_err() {
        let (_srv, addr) =
            start(vec![handler(Fail)], auth_eq("Bearer test")).await;

        let cli = ChanCli::connect(addr, "Bearer test".to_string())
            .await
            .unwrap();

        assert!(cli.request("fail", b"x".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn missing_auth_header_is_unauthorized() {
        let (_srv, addr) =
            start(vec![handler(Echo)], auth_eq("Bearer test")).await;

        // Bypass ChanCli, which always sets the header.
        let res = reqwest::Client::new()
            .post(format!("http://{addr}/echo"))
            .body(b"x".to_vec())
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn multiple_binds() {
        let config = ChanSrvConfig {
            auth_cb: auth_eq("Bearer test"),
            handlers: vec![handler(Echo)],
            bind: vec![
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            ],
        };

        let srv = ChanSrv::new(config).await.unwrap();
        assert_eq!(srv.local_addrs().len(), 2);
    }

    #[tokio::test]
    async fn duplicate_handler_is_err() {
        let config = ChanSrvConfig {
            auth_cb: auth_eq("Bearer test"),
            handlers: vec![handler(Echo), handler(Echo)],
            bind: vec!["127.0.0.1:0".parse().unwrap()],
        };

        assert!(ChanSrv::new(config).await.is_err());
    }
}
