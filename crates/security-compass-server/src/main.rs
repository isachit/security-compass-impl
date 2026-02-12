//! Binary entry point for the Security Compass Server.
//!
//! Starts an axum HTTP server with:
//! - OpenAI-compatible chat completion endpoints
//! - Session management with configurable TTL
//! - Background task for expired session eviction
//! - CORS support
//! - Graceful shutdown on SIGINT

use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::Router;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use security_compass_server::handler::{
    handle_chat_completions, handle_chat_completions_default, handle_langgraph_stub, AppState,
};
use security_compass_server::session_store::SessionStore;

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Read configuration from environment variables.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let server_api_key = std::env::var("SEQURITY_API_KEY").ok().filter(|s| !s.is_empty());

    let session_ttl_secs: u64 = std::env::var("SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800);

    // Create the session store and application state.
    let session_store = SessionStore::new(Duration::from_secs(session_ttl_secs));
    let state = Arc::new(AppState {
        session_store,
        server_api_key,
    });

    // Spawn a background task to periodically evict expired sessions.
    let eviction_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            eviction_state.session_store.evict_expired();
            tracing::debug!(
                "Session eviction complete. Active sessions: {}",
                eviction_state.session_store.len()
            );
        }
    });

    // Build the axum router.
    let app = Router::new()
        .route(
            "/control/v1/chat/completions",
            post(handle_chat_completions_default),
        )
        .route(
            "/control/{provider}/v1/chat/completions",
            post(handle_chat_completions),
        )
        .route(
            "/control/lang-graph/{provider}/v1/chat/completions",
            post(handle_langgraph_stub),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start the server with graceful shutdown.
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind to address");

    tracing::info!("Security Compass Server listening on 0.0.0.0:{port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server failed");
}

/// Waits for the SIGINT (Ctrl+C) signal for graceful shutdown.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    tracing::info!("Received SIGINT, shutting down gracefully...");
}
