//! Per-request tenant identity, set by auth middleware.
//!
//! HTTP handlers extract [`Tenant`] from request extensions and pass its
//! inner string to [`crate::ipam::operations::IpamOps`]. Unauthenticated
//! routes never have it set; tenant-scoped routes are unreachable without
//! it because [`crate::auth::require_auth`] runs first.

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

#[derive(Debug, Clone)]
pub struct Tenant(pub String);

impl Tenant {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Tenant>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "tenant not set"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn extractor_returns_tenant_when_set() {
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(Tenant("a@x".to_string()));
        let (mut parts, _) = req.into_parts();
        let extracted = Tenant::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(extracted.as_str(), "a@x");
    }

    #[tokio::test]
    async fn extractor_returns_401_when_missing() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let result = Tenant::from_request_parts(&mut parts, &()).await;
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }
}
