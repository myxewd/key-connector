use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

use crate::error::ApiError;
use crate::jwt::{bearer_from_header, TokenVerifier};
use crate::store::KeyStore;

/// A master key is 32 bytes, which is 44 characters of base64. Cap the accepted
/// string well above that so an oversized payload fails before it is decoded.
const MAX_KEY_B64_LEN: usize = 512;
/// The JSON body only ever carries a short key; keep the whole request tiny.
const MAX_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub verifier: TokenVerifier,
    pub store: KeyStore,
}

#[derive(Serialize)]
struct UserKeyResponse {
    key: String,
}

#[derive(Deserialize)]
struct UserKeyRequest {
    key: String,
}

pub fn router(state: AppState, allowed_origins: &[String], api_prefix: &str) -> Router {
    Router::new()
        .route(&format!("{api_prefix}/alive"), get(alive))
        .route(
            &format!("{api_prefix}/user-keys"),
            get(get_user_keys).post(post_user_keys),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(cors(allowed_origins))
        .with_state(state)
}

// The web vault runs on a different origin than the connector, so the clients
// need CORS to reach /user-keys. CORS is opt in: an empty allow list accepts no
// browser origin at all, so a connector that was never configured cannot be
// reached from an arbitrary web page. Auth is a bearer token, not a cookie, and
// request headers are mirrored because the clients send a handful of their own.
fn cors(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(AllowHeaders::mirror_request())
}

async fn alive() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let token = bearer_from_header(header)?;
    Ok(state.verifier.verify(token)?.sub)
}

// The stored value is a master key and must never end up in a browser or proxy
// cache.
fn no_store(body: impl IntoResponse) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        body,
    )
}

// The protocol says the connector treats the key as opaque, but accepting only
// a well formed 32 byte base64 key keeps garbage and oversized rows out of the
// database without affecting real clients.
fn validate_key(raw: &str) -> Result<&str, ApiError> {
    let key = raw.trim();
    if key.is_empty() || key.len() > MAX_KEY_B64_LEN {
        return Err(ApiError::InvalidKey);
    }
    match BASE64.decode(key) {
        Ok(bytes) if bytes.len() == 32 => Ok(key),
        _ => Err(ApiError::InvalidKey),
    }
}

async fn get_user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = authenticate(&state, &headers)?;
    match state.store.get(&user_id).await {
        Ok(Some(key)) => Ok(no_store(Json(UserKeyResponse { key }))),
        Ok(None) => Err(ApiError::KeyNotFound),
        Err(e) => {
            tracing::error!(error = %e, "failed to read user key");
            Err(ApiError::Internal)
        }
    }
}

async fn post_user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = authenticate(&state, &headers)?;
    let key = validate_key(&body.key)?;
    state.store.set(&user_id, key).await.map_err(|e| {
        tracing::error!(error = %e, "failed to store user key");
        ApiError::Internal
    })?;
    Ok(no_store(StatusCode::OK))
}
