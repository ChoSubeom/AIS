//! AIS proxy binary entry point.

use ais_proxy::{AppState, ProxyConfig};

#[tokio::main]
async fn main() {
    let backend_url =
        std::env::var("AIS_BACKEND_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let bind_addr = std::env::var("AIS_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let state = AppState::new(ProxyConfig { backend_url });
    let app = ais_proxy::build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind");

    eprintln!("AIS proxy listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.expect("server error");
}
