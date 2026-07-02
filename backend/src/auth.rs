//! API key authentication middleware.
//!
//! When the `ORKID_API_KEY` environment variable is set, all requests (except
//! the health endpoint) must include an `x-api-key` header matching the
//! configured value. When the variable is unset or empty, the backend runs in
//! "dev mode" and allows all requests through.

use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// The header name clients must use to present the API key.
pub const API_KEY_HEADER: &str = "x-api-key";

/// The environment variable that configures the expected API key.
pub const API_KEY_ENV: &str = "ORKID_API_KEY";

/// Middleware that enforces API key authentication.
///
/// - `/api/health` is always exempt so health checks work without a key.
/// - If `ORKID_API_KEY` is unset/empty, all requests are allowed (dev mode).
/// - If set, requests without a matching `x-api-key` header are rejected with
///   `401 Unauthorized`.
pub async fn require_api_key(req: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode> {
    // Skip auth for the health endpoint so liveness probes work unauthenticated.
    if req.uri().path() == "/api/health" {
        return Ok(next.run(req).await);
    }

    let expected_key = std::env::var(API_KEY_ENV);
    match expected_key {
        Ok(key) if !key.is_empty() => {
            let provided = req
                .headers()
                .get(API_KEY_HEADER)
                .and_then(|v| v.to_str().ok());
            if provided == Some(key.as_str()) {
                Ok(next.run(req).await)
            } else {
                tracing::warn!(
                    path = %req.uri().path(),
                    "rejected request: missing or invalid API key"
                );
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => {
            // Dev mode: no API key configured, allow all requests.
            Ok(next.run(req).await)
        }
    }
}
