#![deny(missing_docs)]
//! v-m.io backend server

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::io::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;

const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
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

/// Start a server.
pub async fn serve() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let builder = auto::Builder::new(TokioExecutor::new());

            if let Err(err) = builder
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

use lru::LruCache;
use mlua::prelude::*;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::thread;

struct ThreadScriptCache {
    cache: LruCache<String, LuaRegistryKey>,
}

impl ThreadScriptCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
        }
    }

    pub fn get_or_compile(
        &mut self,
        lua: &Lua,
        name: &str,
        source: &str,
    ) -> LuaResult<LuaFunction> {
        if let Some(key) = self.cache.get(name)
            && let Ok(func) = lua.registry_value::<LuaFunction>(key)
        {
            return Ok(func);
        }

        let bytecode_func = lua.load(source).into_function()?;

        let key = lua.create_registry_value(bytecode_func.clone())?;
        self.cache.put(name.to_string(), key);

        Ok(bytecode_func)
    }
}

thread_local! {
    static LUA_ENGINE: RefCell<Lua> = RefCell::new(Lua::new());
    static SCRIPT_CACHE: RefCell<ThreadScriptCache> =
        RefCell::new(ThreadScriptCache::new(100));
}

// =========================================================================
// 3. SANDBOXED EXECUTION ENGINE
// =========================================================================
fn execute_client_script(
    client_id: &str,
    script_name: &str,
    source: &str,
) -> LuaResult<()> {
    LUA_ENGINE.with(|lua_cell| {
        SCRIPT_CACHE.with(|cache_cell| {
            let lua = lua_cell.borrow();
            let mut cache = cache_cell.borrow_mut();

            // Step A: Fetch or compile the reusable function chunk from the LRU cache
            let compiled_func =
                cache.get_or_compile(&lua, script_name, source)?;

            // Step B: Create a brand new, isolated environment table for this invocation
            let sandbox_env = lua.create_table()?;

            // Step C: Link the global environment as a read-only fallback via metatables
            let meta = lua.create_table()?;
            meta.set("__index", lua.globals())?;
            sandbox_env.set_metatable(Some(meta)).unwrap();

            // Inject request-specific contextual variables cleanly into the client sandbox
            sandbox_env.set("CLIENT_ID", client_id)?;

            // =========================================================================
            // FIXED: Call `.set_environment(env)` directly on the function instance.
            // =========================================================================
            compiled_func.set_environment(sandbox_env.clone())?;

            // Step E: Execute the script safely
            compiled_func.call::<()>(())?;

            // Step F: Proof of containment
            if let Ok(leaked_var) =
                sandbox_env.get::<Option<String>>("user_variable")
            {
                println!(
                    "[Thread Code] Client '{}' stored local context data: {:?}",
                    client_id, leaked_var
                );
            }

            Ok(())
        })
    })
}

// =========================================================================
// 4. VERIFICATION RUN
// =========================================================================
/// yo
pub fn lua_test() {
    let mut worker_threads = vec![];

    for thread_num in 0..2 {
        worker_threads.push(thread::spawn(move || {
            let dynamic_script = r#"
                user_variable = "Data leaked from " .. CLIENT_ID
                print(string.format("[VM Exec] Runtime thread %d executing script for client: %s", thread_id_injected, CLIENT_ID))
            "#;

            LUA_ENGINE.with(|lua_cell| {
                lua_cell.borrow().globals().set("thread_id_injected", thread_num).unwrap();
            });

            execute_client_script("Alice", "shared_analytics_v1", dynamic_script).unwrap();
            execute_client_script("Bob", "shared_analytics_v1", dynamic_script).unwrap();

            LUA_ENGINE.with(|lua_cell| {
                let lua = lua_cell.borrow();
                let true_global: Option<String> = lua.globals().get("user_variable").unwrap();
                assert!(true_global.is_none(), "CRITICAL FAILURE: Global contamination detected inside VM!");
            });
        }));
    }

    for thread in worker_threads {
        thread.join().unwrap();
    }

    println!("Execution completed cleanly without any state leakage.");
}
