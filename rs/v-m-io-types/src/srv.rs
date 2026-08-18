//! server types

use std::collections::BTreeSet;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let auth_header = req.headers().get(AUTHORIZATION);

    if let Err(err_resp) = validate_token(auth_header) {
        return Ok(*err_resp);
    }

    let body = req.into_body();
    let limited_body = Limited::new(body, MAX_BODY);

    let bytes = match limited_body.collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(err) => {
            let mut error_response = Response::new(Full::new(Bytes::new()));

            if err.downcast_ref::<LengthLimitError>().is_some() {
                *error_response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                *error_response.body_mut() = Full::new(Bytes::from(
                    "Error: Payload exceeds maximum size limit.",
                ));
            } else {
                *error_response.status_mut() = StatusCode::BAD_REQUEST;
                *error_response.body_mut() = Full::new(Bytes::from(
                    "Error: Failed to read stream or malformed payload.",
                ));
            }

            return Ok(error_response);
        }
    };

    Ok(Response::new(Full::new(Bytes::from(format!(
        "Hello over HTTP/2! {}\n",
        bytes.len()
    )))))
}

fn validate_token(
    auth_header: Option<&HeaderValue>,
) -> std::result::Result<(), Box<Response<Full<Bytes>>>> {
    let build_error = |msg: &'static str| {
        let mut res = Response::new(Full::new(Bytes::from(msg)));
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Box::new(res)
    };

    let header_val = match auth_header {
        Some(val) => val,
        None => {
            return Err(build_error("Error: Missing Authorization header."));
        }
    };

    let header_str = match header_val.to_str() {
        Ok(s) => s,
        Err(_) => return Err(build_error("Error: Invalid header encoding.")),
    };

    if !header_str.starts_with("Bearer ") {
        return Err(build_error(
            "Error: Authorization format must be 'Bearer <token>'.",
        ));
    }

    let token = &header_str[7..];

    if token != "your_secure_secret_token" {
        return Err(build_error("Error: Invalid or expired token."));
    }

    Ok(())
}

/// Start a server.
pub async fn serve(bind: Vec<SocketAddr>) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(2048));

    let listeners = futures_util::future::try_join_all(
        bind.into_iter().map(TcpListener::bind),
    )
    .await?
    .into_iter()
    .map(|listener| {
        println!(
            "listening on: http://{}",
            listener.local_addr().expect("local addr")
        );
        tokio_stream::wrappers::TcpListenerStream::new(listener)
    });

    let mut listeners = futures_util::stream::select_all(listeners);

    loop {
        use futures_util::StreamExt;

        let stream = match listeners.next().await {
            None => return Err(std::io::Error::other("all listeners halted")),
            Some(s) => s?,
        };

        let io = TokioIo::new(stream);
        let limit = limit.clone();

        tokio::task::spawn(async move {
            let builder = auto::Builder::new(TokioExecutor::new());

            let _permit = match tokio::time::timeout(
                std::time::Duration::from_millis(17),
                limit.clone().acquire_owned(),
            )
            .await
            {
                Err(_) => {
                    let _ = builder
                        .serve_connection(
                            io,
                            service_fn(|_| async {
                                let mut res = Response::new(
                                    "Service Unavailable".to_string(),
                                );
                                *res.status_mut() =
                                    StatusCode::SERVICE_UNAVAILABLE;
                                res.headers_mut().insert(
                                    hyper::header::RETRY_AFTER,
                                    hyper::header::HeaderValue::from_static(
                                        "60",
                                    ),
                                );
                                Ok::<_, std::convert::Infallible>(res)
                            }),
                        )
                        .await;
                    return;
                }
                Ok(r) => r.map_err(std::io::Error::other),
            };

            if let Err(err) = builder
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// Cluster info.
#[derive(Default)]
pub struct ClusterInfo {
    srv_set: BTreeSet<std::net::SocketAddr>,
}

impl ClusterInfo {
    /// Add a known server to the cluster list.
    pub fn add_server(&mut self, addr: std::net::SocketAddr) {
        self.srv_set.insert(addr);
    }

    /// Pick server for given identifier.
    pub fn server_for_id(&self, id: &[u8]) -> std::net::SocketAddr {
        *self
            .srv_set
            .iter()
            .nth(gen_shard_index(id, self.srv_set.len()))
            .unwrap_or_else(|| self.srv_set.first().expect("empty cluster"))
    }
}

fn gen_shard_index(data: &[u8], total_servers: usize) -> usize {
    if total_servers == 0 {
        return 0;
    }

    let mut hash: u32 = 0xadc83b19;

    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;

    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let mut k = u32::from_le_bytes(chunk.try_into().unwrap());

        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    if !remainder.is_empty() {
        let mut k: u32 = 0;

        for &byte in remainder.iter().rev() {
            k = (k << 8) | (byte as u32);
        }
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        hash ^= k;
    }

    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash as usize % total_servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_test() {
        let servers_count = 5;

        let keys = [
            b"user_id_0001",
            b"user_id_0002",
            b"user_id_0003",
            b"user_id_0004",
        ];

        for key in keys {
            let name = String::from_utf8_lossy(key);
            println!(
                "Key: '{}' -> Server Index: {}",
                name,
                gen_shard_index(key, servers_count)
            );
        }
    }
}
