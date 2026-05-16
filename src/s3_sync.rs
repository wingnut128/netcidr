//! S3-backed SQLite sync for the Lambda deployment.
//!
//! On Lambda cold start, `S3Syncer::pull` downloads the SQLite database from
//! S3 to a local `/tmp` path. After every mutating HTTP request, `push`
//! uploads the database back so the next invocation starts with current state.
//!
//! Uses manual AWS Signature Version 4 (reqwest + sha2 + hmac) to avoid
//! pulling in the entire aws-sdk-s3 crate tree.
//!
//! **Concurrency warning**: set Lambda `reserved_concurrency = 1` on the
//! function to prevent two concurrent containers from diverging and
//! overwriting each other's writes.

use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{NetcidrError, Result};

type HmacSha256 = Hmac<Sha256>;

pub struct S3Syncer {
    client: Client,
    bucket: String,
    key: String,
    region: String,
    pub db_path: String,
}

struct AwsCreds {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

impl AwsCreds {
    fn from_env() -> Result<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| NetcidrError::InvalidInput("AWS_ACCESS_KEY_ID not set".into()))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| NetcidrError::InvalidInput("AWS_SECRET_ACCESS_KEY not set".into()))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        Ok(Self {
            access_key,
            secret_key,
            session_token,
        })
    }
}

impl S3Syncer {
    pub fn new(bucket: String, key: String, db_path: String) -> Self {
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".into());
        Self {
            client: Client::new(),
            bucket,
            key,
            db_path,
            region,
        }
    }

    fn host(&self) -> String {
        format!("{}.s3.{}.amazonaws.com", self.bucket, self.region)
    }

    fn canonical_uri(&self) -> String {
        format!("/{}", uri_encode(&self.key, false))
    }

    fn signed_headers(
        &self,
        method: &str,
        creds: &AwsCreds,
        payload: &[u8],
    ) -> Vec<(String, String)> {
        let now = Utc::now();
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();

        let host = self.host();
        let payload_hash = sha256_hex(payload);

        let mut header_entries: Vec<(String, String)> = vec![
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), datetime_str.clone()),
        ];
        if let Some(token) = &creds.session_token {
            header_entries.push(("x-amz-security-token".to_string(), token.clone()));
        }
        header_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = header_entries
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect();
        let signed_headers: String = header_entries
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{method}\n{}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            self.canonical_uri()
        );

        let credential_scope = format!("{date_str}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime_str}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k = derive_signing_key(&creds.secret_key, &date_str, &self.region);
        let signature = hex_hmac_sha256(&k, string_to_sign.as_bytes());

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key
        );

        let mut result = vec![
            ("x-amz-date".to_string(), datetime_str),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("Authorization".to_string(), authorization),
        ];
        if let Some(token) = &creds.session_token {
            result.push(("x-amz-security-token".to_string(), token.clone()));
        }
        result
    }

    /// Download the SQLite DB from S3 to `self.db_path`.
    ///
    /// Returns `false` when the object does not exist yet (first deployment);
    /// the SQLite store will then create a fresh database on `initialize`.
    pub async fn pull(&self) -> Result<bool> {
        let creds = AwsCreds::from_env()?;
        let headers = self.signed_headers("GET", &creds, b"");
        let url = format!("https://{}{}", self.host(), self.canonical_uri());

        let mut req = self.client.get(&url);
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let resp = req.send().await.map_err(|e| {
            NetcidrError::DatabaseError(format!("S3 GetObject request failed: {e}"))
        })?;

        match resp.status().as_u16() {
            200 => {
                let bytes = resp.bytes().await.map_err(|e| {
                    NetcidrError::DatabaseError(format!("S3 GetObject read failed: {e}"))
                })?;
                tokio::fs::write(&self.db_path, &bytes)
                    .await
                    .map_err(NetcidrError::Io)?;
                info!(bytes = bytes.len(), key = %self.key, "pulled SQLite DB from S3");
                Ok(true)
            }
            404 => {
                warn!(
                    key = %self.key,
                    "DB object not found in S3 — starting with fresh database"
                );
                Ok(false)
            }
            status => {
                let body = resp.text().await.unwrap_or_default();
                Err(NetcidrError::DatabaseError(format!(
                    "S3 GetObject failed ({status}): {body}"
                )))
            }
        }
    }

    /// Upload the current SQLite DB from `self.db_path` to S3.
    pub async fn push(&self) -> Result<()> {
        let bytes = tokio::fs::read(&self.db_path)
            .await
            .map_err(NetcidrError::Io)?;
        let len = bytes.len();

        let creds = AwsCreds::from_env()?;
        let headers = self.signed_headers("PUT", &creds, &bytes);
        let url = format!("https://{}{}", self.host(), self.canonical_uri());

        let mut req = self.client.put(&url).body(bytes);
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let resp = req.send().await.map_err(|e| {
            NetcidrError::DatabaseError(format!("S3 PutObject request failed: {e}"))
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(NetcidrError::DatabaseError(format!(
                "S3 PutObject failed ({status}): {body}"
            )));
        }

        info!(bytes = len, key = %self.key, "pushed SQLite DB to S3");
        Ok(())
    }
}

/// Returns true for HTTP methods that mutate state and require an S3 push.
pub fn is_write_method(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET
            | axum::http::Method::HEAD
            | axum::http::Method::OPTIONS
            | axum::http::Method::TRACE
    )
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hex_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    let key = format!("AWS4{secret_key}");
    let k_date = hmac_sha256_bytes(key.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256_bytes(&k_date, region.as_bytes());
    let k_service = hmac_sha256_bytes(&k_region, b"s3");
    hmac_sha256_bytes(&k_service, b"aws4_request")
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn write_methods_identified_correctly() {
        assert!(is_write_method(&Method::POST));
        assert!(is_write_method(&Method::PUT));
        assert!(is_write_method(&Method::PATCH));
        assert!(is_write_method(&Method::DELETE));
    }

    #[test]
    fn read_methods_not_flagged_as_writes() {
        assert!(!is_write_method(&Method::GET));
        assert!(!is_write_method(&Method::HEAD));
        assert!(!is_write_method(&Method::OPTIONS));
    }

    #[test]
    fn uri_encode_preserves_slashes_in_key() {
        assert_eq!(
            uri_encode("netcidr/netcidr.db", false),
            "netcidr/netcidr.db"
        );
    }

    #[test]
    fn uri_encode_encodes_slashes_when_requested() {
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn sha256_hex_empty() {
        // SHA-256 of empty input is the well-known constant used in SigV4 for empty payloads
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
