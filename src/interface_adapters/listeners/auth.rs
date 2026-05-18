//! Shared bearer-token authentication middleware for all HTTP-based listeners
//! (API server, MCP server). When an `api_token` is configured, requests must
//! include a valid `Authorization: Bearer <token>` header. Token comparison is
//! constant-time to prevent timing side-channel attacks.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json;

/// Axum middleware that validates a `Bearer` token from the `Authorization`
/// header. When `token` is `None`, no authentication is enforced and all
/// requests pass through.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub async fn bearer_auth_middleware(
    request: Request,
    next: Next,
    token: Arc<Option<String>>,
) -> Response {
    if let Some(ref expected) = *token {
        let expected_header = format!("Bearer {expected}");
        match request.headers().get("authorization") {
            Some(value) => {
                let value = value.to_str().unwrap_or("");
                if !constant_time_eq(value.as_bytes(), expected_header.as_bytes()) {
                    return auth_error(StatusCode::UNAUTHORIZED, "invalid authorization token");
                }
            }
            None => {
                return auth_error(StatusCode::UNAUTHORIZED, "authorization header required");
            }
        }
    }
    next.run(request).await
}

/// Constant-time comparison to prevent timing side-channel attacks on token
/// validation. Returns `true` when both slices are equal.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Build a JSON error response for authentication failures.
fn auth_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({
        "success": false,
        "error": message,
    });
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_slices() {
        assert!(constant_time_eq(b"secret", b"secret"));
    }

    #[test]
    fn constant_time_eq_rejects_unequal_slices() {
        assert!(!constant_time_eq(b"secret", b"wrong!"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_handles_empty_slices() {
        assert!(constant_time_eq(b"", b""));
    }
}
