//! Bearer-token protection for the admin HTTP routes.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ring::digest;

use crate::config::{env_secret, ConfigError};

const MIN_TOKEN_LEN: usize = 16;

/// A bearer token (min. 16 bytes). Only its SHA-256 is kept; comparison is
/// constant-time over the digests, so neither content nor length leaks.
#[derive(Clone)]
pub struct ApiToken(Arc<[u8; 32]>);

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, b);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

impl ApiToken {
    pub fn new(token: &str) -> Result<Self, ConfigError> {
        let t = token.trim();
        if t.len() < MIN_TOKEN_LEN {
            return Err(ConfigError::Invalid(format!(
                "API token must be at least {MIN_TOKEN_LEN} bytes"
            )));
        }
        Ok(ApiToken(Arc::new(sha256(t.as_bytes()))))
    }

    /// Reads the token from the environment variable `var`.
    pub fn from_env(var: &str) -> Result<Self, ConfigError> {
        Self::new(&env_secret(var)?)
    }

    pub fn verify(&self, presented: &str) -> bool {
        let p = sha256(presented.as_bytes());
        p.iter()
            .zip(self.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

/// axum middleware: rejects requests without a valid `Authorization: Bearer`.
pub async fn require_bearer(State(token): State<ApiToken>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| token.verify(t.trim()));
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            axum::Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rules() {
        assert!(ApiToken::new("short").is_err());
        let t = ApiToken::new("0123456789abcdef").unwrap();
        assert!(t.verify("0123456789abcdef"));
        assert!(!t.verify("0123456789abcdeF"));
        assert!(!t.verify(""));
        assert_eq!(format!("{t:?}"), "ApiToken(<redacted>)");
    }
}
