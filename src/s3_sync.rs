//! S3-backed SQLite sync for the Lambda deployment.
//!
//! On Lambda cold start, `S3Syncer::pull` downloads the SQLite database from
//! S3 to a local `/tmp` path. After every mutating HTTP request, `push`
//! uploads the database back so the next invocation starts with current state.
//!
//! **Concurrency warning**: set Lambda `reserved_concurrency = 1` on the
//! function to prevent two concurrent containers from diverging and
//! overwriting each other's writes.

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use tracing::{info, warn};

use crate::error::{NetcidrError, Result};

pub struct S3Syncer {
    client: aws_sdk_s3::Client,
    bucket: String,
    key: String,
    pub db_path: String,
}

impl S3Syncer {
    pub async fn new(bucket: String, key: String, db_path: String) -> Self {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_s3::Client::new(&sdk_config);
        Self {
            client,
            bucket,
            key,
            db_path,
        }
    }

    /// Download the SQLite DB from S3 to `self.db_path`.
    ///
    /// Returns `false` when the object does not exist yet (first deployment);
    /// the SQLite store will then create a fresh database on `initialize`.
    pub async fn pull(&self) -> Result<bool> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
        {
            Ok(output) => {
                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?
                    .into_bytes();
                tokio::fs::write(&self.db_path, &bytes)
                    .await
                    .map_err(NetcidrError::Io)?;
                info!(
                    bytes = bytes.len(),
                    key = %self.key,
                    "pulled SQLite DB from S3"
                );
                Ok(true)
            }
            Err(SdkError::ServiceError(svc)) if svc.err().is_no_such_key() => {
                warn!(key = %self.key, "DB object not found in S3 — starting with fresh database");
                Ok(false)
            }
            Err(e) => Err(NetcidrError::DatabaseError(format!(
                "S3 GetObject failed: {e}"
            ))),
        }
    }

    /// Upload the current SQLite DB from `self.db_path` to S3.
    pub async fn push(&self) -> Result<()> {
        let bytes = tokio::fs::read(&self.db_path)
            .await
            .map_err(NetcidrError::Io)?;
        let len = bytes.len();
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("S3 PutObject failed: {e}")))?;
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
}
