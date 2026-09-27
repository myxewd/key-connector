use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("missing or malformed Authorization header")]
    MissingToken,
    /// The low-level decoder detail is kept for logs and never returned to the
    /// client.
    #[error("invalid access token: {0}")]
    InvalidToken(String),
    #[error("invalid key: expected base64 of a 32 byte master key")]
    InvalidKey,
    #[error("no key stored for this user")]
    KeyNotFound,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::MissingToken | ApiError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            ApiError::InvalidKey => StatusCode::BAD_REQUEST,
            ApiError::KeyNotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Keep the underlying JWT/decoding failure in the logs; the client only
        // needs to know the token was not accepted.
        let message = match &self {
            ApiError::InvalidToken(detail) => {
                tracing::debug!(detail = %detail, "rejected access token");
                "invalid access token".to_string()
            }
            other => other.to_string(),
        };
        // the clients expect a JSON object body
        let body = Json(json!({ "message": message }));
        (status, body).into_response()
    }
}
