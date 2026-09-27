mod config;
mod crypto;
mod error;
mod jwt;
mod routes;
mod store;
mod util;

#[cfg(test)]
mod tests;

use config::Config;
use crypto::KeyCipher;
use jwt::TokenVerifier;
use routes::AppState;
use store::KeyStore;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "key_connector=info,tower_http=info".into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    tracing::info!(bind = %cfg.bind_addr, "starting key-connector");

    let verifier = TokenVerifier::from_config(&cfg).await?;
    let cipher = KeyCipher::new(&cfg.encryption_key)?;
    let database_url = util::redact_database_url(&cfg.database_url);
    let store = KeyStore::connect(&cfg.database_url, cipher)
        .await
        .map_err(|e| format!("failed to open database '{database_url}': {e}"))?;

    if cfg.cors_allowed_origins.is_empty() {
        tracing::warn!(
            "KC_CORS_ALLOWED_ORIGINS is empty; browser requests from every origin will be rejected. \
             Set it to the web vault origin, e.g. https://vault.example.com"
        );
    }

    let app = routes::router(
        AppState { verifier, store },
        &cfg.cors_allowed_origins,
        &cfg.api_prefix,
    )
    .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", cfg.bind_addr))?;

    tracing::info!("listening on {}", cfg.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
