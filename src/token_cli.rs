//! `netcidr token …` CLI handler. Talks to a remote `netcidr serve`
//! instance over the `/me/tokens` REST endpoints (Phase 4). Auth comes
//! from the `NETCIDR_API_TOKEN` env var (a PAT or a static bearer);
//! the API base URL comes from `NETCIDR_API_URL` or the `--api-url` flag.
//!
//! The HTTP client is intentionally local to this module rather than
//! reusing `mcp_client::HttpIpamClient`, because that client targets
//! `/ipam/*` and never carries an `Authorization` header — adding one
//! conditionally would muddy its single-purpose design.

use netcidr::auth::Role;
use netcidr::cli::TokenCommands;
use netcidr::error::{NetcidrError, Result};
use netcidr::ipam::models::PersonalAccessTokenSummary;
use netcidr::me_api::{CreateTokenRequest, CreateTokenResponse, TokenListResponse};
use netcidr::output::{CsvOutput, OutputWriter, TextOutput};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::print_stdout;

const ENV_API_URL: &str = "NETCIDR_API_URL";
const ENV_API_TOKEN: &str = "NETCIDR_API_TOKEN";

/// Wrapper for JSON error responses from the API. Mirrors the body
/// shape used by `me_api::ErrorBody` (`{ "error": "..." }`).
#[derive(Deserialize)]
struct ApiError {
    error: String,
}

struct TokenClient {
    client: Client,
    base_url: String,
    bearer: String,
}

impl TokenClient {
    fn new(base_url: String, bearer: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| NetcidrError::InvalidInput(format!("HTTP client error: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Map a non-success HTTP response from `netcidr serve` to an
    /// `Upstream { status, message }`. The CLI surfaces the resulting
    /// error via its Display impl ("upstream error (HTTP 401): …"), so
    /// the user gets both the status class and the upstream's chosen
    /// message without this layer doing its own classification.
    async fn map_error(resp: reqwest::Response) -> NetcidrError {
        let status = resp.status().as_u16();
        let message = resp
            .json::<ApiError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {status}"));
        NetcidrError::Upstream { status, message }
    }

    async fn list(&self) -> Result<TokenListResponse> {
        let resp = self
            .client
            .get(self.url("/me/tokens"))
            .bearer_auth(&self.bearer)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    async fn create(&self, req: &CreateTokenRequest) -> Result<CreateTokenResponse> {
        let resp = self
            .client
            .post(self.url("/me/tokens"))
            .bearer_auth(&self.bearer)
            .json(req)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    async fn revoke(&self, id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/me/tokens/{id}")))
            .bearer_auth(&self.bearer)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_error(resp).await)
        }
    }
}

// --- Output views -----------------------------------------------------------
//
// We wrap the wire types in CLI-local view structs so we can implement the
// project's `TextOutput` / `CsvOutput` traits without touching me_api. JSON
// and YAML output go through Serialize on the same view types — so the user-
// facing schema is a deliberate CLI surface, separate from the wire schema.

#[derive(Serialize)]
struct TokenListView {
    tokens: Vec<PersonalAccessTokenSummary>,
    count: usize,
}

impl From<TokenListResponse> for TokenListView {
    fn from(r: TokenListResponse) -> Self {
        Self {
            tokens: r.tokens,
            count: r.count,
        }
    }
}

impl TextOutput for TokenListView {
    fn to_text(&self) -> String {
        if self.tokens.is_empty() {
            return "No tokens.\n".to_string();
        }
        let mut out = String::new();
        out.push_str(&format!(
            "{:<36}  {:<12}  {:<24}  {:<10}  {:<25}  {:<25}  {:<25}  {}\n",
            "ID", "PREFIX", "NAME", "ROLE", "CREATED", "EXPIRES", "LAST USED", "STATUS"
        ));
        for t in &self.tokens {
            let status = if t.revoked_at.is_some() {
                "revoked"
            } else {
                "active"
            };
            out.push_str(&format!(
                "{:<36}  {:<12}  {:<24}  {:<10}  {:<25}  {:<25}  {:<25}  {}\n",
                t.id,
                t.prefix,
                t.name,
                t.role.as_str(),
                t.created_at,
                t.expires_at,
                t.last_used_at.as_deref().unwrap_or("never"),
                status
            ));
        }
        out.push_str(&format!("\n{} token(s)\n", self.count));
        out
    }
}

impl CsvOutput for TokenListView {
    fn to_csv(&self) -> Result<String> {
        let mut out =
            String::from("id,prefix,name,role,created_at,expires_at,last_used_at,revoked_at\n");
        for t in &self.tokens {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                t.id,
                t.prefix,
                csv_escape(&t.name),
                t.role.as_str(),
                t.created_at,
                t.expires_at,
                t.last_used_at.as_deref().unwrap_or(""),
                t.revoked_at.as_deref().unwrap_or("")
            ));
        }
        Ok(out)
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[derive(Serialize)]
struct CreateTokenView {
    id: String,
    name: String,
    prefix: String,
    role: Role,
    token: String,
    created_at: String,
    expires_at: String,
}

impl From<CreateTokenResponse> for CreateTokenView {
    fn from(r: CreateTokenResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            prefix: r.prefix,
            role: r.role,
            token: r.token,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

impl TextOutput for CreateTokenView {
    fn to_text(&self) -> String {
        format!(
            "Token created.\n\n  id:         {}\n  name:       {}\n  prefix:     {}\n  role:       {}\n  created_at: {}\n  expires_at: {}\n\n\
             Save this token now — it will NOT be shown again:\n\n  {}\n",
            self.id,
            self.name,
            self.prefix,
            self.role.as_str(),
            self.created_at,
            self.expires_at,
            self.token
        )
    }
}

impl CsvOutput for CreateTokenView {
    fn to_csv(&self) -> Result<String> {
        Ok(format!(
            "id,name,prefix,role,created_at,expires_at,token\n{},{},{},{},{},{},{}\n",
            self.id,
            csv_escape(&self.name),
            self.prefix,
            self.role.as_str(),
            self.created_at,
            self.expires_at,
            self.token
        ))
    }
}

#[derive(Serialize)]
struct RevokeView {
    id: String,
    revoked: bool,
}

impl TextOutput for RevokeView {
    fn to_text(&self) -> String {
        format!("Revoked token {}\n", self.id)
    }
}

impl CsvOutput for RevokeView {
    fn to_csv(&self) -> Result<String> {
        Ok(format!("id,revoked\n{},{}\n", self.id, self.revoked))
    }
}

// --- Dispatch ---------------------------------------------------------------

fn resolve_api_url(cli_flag: Option<&str>) -> Result<String> {
    if let Some(url) = cli_flag {
        return Ok(url.to_string());
    }
    std::env::var(ENV_API_URL).map_err(|_| {
        NetcidrError::InvalidInput(format!("no API URL — pass --api-url or set {ENV_API_URL}"))
    })
}

fn resolve_bearer() -> Result<String> {
    let token = std::env::var(ENV_API_TOKEN).map_err(|_| {
        NetcidrError::InvalidInput(format!(
            "no auth token — set {ENV_API_TOKEN} (a PAT or static bearer)"
        ))
    })?;
    if token.trim().is_empty() {
        return Err(NetcidrError::InvalidInput(format!(
            "{ENV_API_TOKEN} is empty"
        )));
    }
    Ok(token)
}

fn write_view<T: Serialize + TextOutput + CsvOutput>(
    writer: &OutputWriter,
    output_file: &Option<String>,
    view: &T,
) -> Result<()> {
    let s = writer
        .write(view)
        .map_err(|e| NetcidrError::InvalidInput(e.to_string()))?;
    if output_file.is_none() {
        print_stdout(&s);
    }
    Ok(())
}

pub async fn handle_token_command(
    writer: &OutputWriter,
    output_file: &Option<String>,
    api_url: Option<&str>,
    command: TokenCommands,
) -> Result<()> {
    let base = resolve_api_url(api_url)?;
    let bearer = resolve_bearer()?;
    let client = TokenClient::new(base, bearer)?;

    match command {
        TokenCommands::List => {
            let view: TokenListView = client.list().await?.into();
            write_view(writer, output_file, &view)
        }
        TokenCommands::Create {
            name,
            expires_in,
            role,
        } => {
            let expires_in_days = match expires_in.as_deref() {
                Some(s) => Some(parse_human_days(s)?),
                None => None,
            };
            let req = CreateTokenRequest {
                name,
                expires_in_days,
                role,
            };
            let view: CreateTokenView = client.create(&req).await?.into();
            write_view(writer, output_file, &view)
        }
        TokenCommands::Revoke { id } => {
            client.revoke(&id).await?;
            let view = RevokeView { id, revoked: true };
            write_view(writer, output_file, &view)
        }
    }
}

/// Parse a tightly-bounded human-readable duration into days.
///
/// Grammar (case-sensitive, no whitespace, no decimals, no compounds):
///
/// ```text
///   <duration> := <positive-integer> <unit>
///   <unit>     := "d" | "w" | "y"
/// ```
///
/// Units: `d` = 1 day, `w` = 7 days, `y` = 365 days. Leading zeros are
/// rejected (`0d`, `01d` both fail). The result must fit in `u32`; the
/// server enforces its own ≤365-day cap on top of this.
///
/// Deliberately omits `m` (minutes vs months ambiguity) and any
/// composite forms like `1d12h`. The input surface is supposed to be
/// boring.
fn parse_human_days(s: &str) -> Result<u32> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return Err(NetcidrError::InvalidInput(format!(
            "invalid duration {s:?}: expected <N><unit>, e.g. 30d, 12w, 1y"
        )));
    }
    let (digits, unit) = bytes.split_at(bytes.len() - 1);
    let unit = unit[0];

    // Reject leading zeros and non-ASCII-digit bytes outright. `[1-9][0-9]*`.
    if digits[0] == b'0' || !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(NetcidrError::InvalidInput(format!(
            "invalid duration {s:?}: digits must match [1-9][0-9]*"
        )));
    }

    let n: u32 = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            NetcidrError::InvalidInput(format!("invalid duration {s:?}: number out of range"))
        })?;

    let multiplier: u32 = match unit {
        b'd' => 1,
        b'w' => 7,
        b'y' => 365,
        _ => {
            return Err(NetcidrError::InvalidInput(format!(
                "invalid duration {s:?}: unit must be d, w, or y"
            )));
        }
    };

    n.checked_mul(multiplier)
        .ok_or_else(|| NetcidrError::InvalidInput(format!("invalid duration {s:?}: too large")))
}

#[cfg(test)]
mod tests {
    use super::parse_human_days;

    #[test]
    fn accepts_canonical_forms() {
        assert_eq!(parse_human_days("1d").unwrap(), 1);
        assert_eq!(parse_human_days("30d").unwrap(), 30);
        assert_eq!(parse_human_days("1w").unwrap(), 7);
        assert_eq!(parse_human_days("12w").unwrap(), 84);
        assert_eq!(parse_human_days("1y").unwrap(), 365);
    }

    #[test]
    fn rejects_missing_or_unknown_unit() {
        for s in ["", "d", "30", "30s", "30h", "30M", "30D", "30Y"] {
            assert!(parse_human_days(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_leading_zero_and_zero() {
        for s in ["0d", "00d", "01d", "07w"] {
            assert!(parse_human_days(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_non_canonical_shapes() {
        for s in [
            " 1d", "1d ", "1.5d", "1d30m", "1d12h", "+1d", "-1d", "1dd", "1 d", "one-day",
        ] {
            assert!(parse_human_days(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_human_days("99999999999d").is_err());
        // 12000000y * 365 overflows u32.
        assert!(parse_human_days("12000000y").is_err());
    }
}
