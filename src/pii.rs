//! Key-based PII / credential detection shared by every telemetry export path
//! (OTLP spans in `telemetry`, Sentry events in `error_reporting`).

/// Returns true when an attribute key looks like PII or a credential and must
/// be stripped before export. Pattern-based so it also catches fields added by
/// future `#[instrument]` sites (e.g. `owner_email`, `caller_email`). Note that
/// non-sensitive identifiers like `pat_id` (a token *id*, not the secret) are
/// intentionally NOT matched.
pub fn is_pii_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.ends_with("email")
        || k == "sub"
        || k.ends_with("_sub")
        || k.contains("token")
        || k.contains("password")
        || k.contains("secret")
        || k.contains("authorization")
        || k.contains("bearer")
        || k.contains("api_key")
        || k.contains("apikey")
        || k.contains("credential")
        || k.contains("database_url")
}

#[cfg(test)]
mod tests {
    use super::is_pii_key;

    #[test]
    fn flags_identity_and_credential_keys() {
        for k in [
            "email",
            "owner_email",
            "sub",
            "oidc_sub",
            "pat_secret",
            "access_token",
            "Authorization",
            "database_url",
        ] {
            assert!(is_pii_key(k), "expected `{k}` to be flagged as PII");
        }
    }

    #[test]
    fn allows_operational_keys() {
        for k in ["cidr", "prefix", "pat_id", "netcidr.role", "http.route"] {
            assert!(!is_pii_key(k), "expected `{k}` to be allowed");
        }
    }
}
