//! Personal Access Token primitives: generation, hashing, and shape validation.
//!
//! All functions in this module are pure — no I/O, no DB, no clock. The
//! storage layer (`crate::ipam::store::IpamStore`) handles persistence;
//! middleware (`crate::auth`) wires this module to incoming HTTP requests.
//!
//! Token wire format:
//!
//! ```text
//! ncdr_pat_<43 base64url chars>     # 32 random bytes, b64url-no-pad
//! ```
//!
//! The `ncdr_pat_` prefix lets the auth middleware route a `Bearer …`
//! header to the PAT verifier without trial-and-error against OIDC, and
//! makes leaked tokens recognisable to secret scanners (GitHub push
//! protection, etc).

use std::fmt;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::error::{NetcidrError, Result};

/// Environment variable holding the b64url-no-pad encoded server pepper.
pub const PEPPER_ENV: &str = "NETCIDR_PAT_PEPPER";

/// Minimum acceptable pepper length, in raw (decoded) bytes.
///
/// 16 bytes (128 bits) is the floor. The spec recommends 32 bytes; this
/// minimum just rejects obviously-wrong configurations like an empty
/// or near-empty value.
pub const MIN_PEPPER_BYTES: usize = 16;

/// Raw byte length of the random secret embedded in a token.
const SECRET_BYTES: usize = 32;

/// Length of the public token prefix exposed in lists and DB rows:
/// `ncdr_pat_` (9 chars) + 3 random b64url chars = 12 chars total.
const PREFIX_LEN: usize = 12;

/// Wire-format regex used by every verification path. Matching is the
/// gate for any DB lookup; non-matching tokens are rejected without
/// any further work.
pub static PAT_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^ncdr_pat_[A-Za-z0-9_-]{43}$").expect("PAT_SHAPE regex must compile")
});

/// Server-side pepper mixed into every token hash.
///
/// `Debug` is intentionally redacted — pepper bytes must never appear in
/// logs. The inner `Box<[u8]>` is `pub(crate)`-only via `as_slice`.
pub struct PatPepper(Box<[u8]>);

impl fmt::Debug for PatPepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PatPepper(<redacted>)")
    }
}

impl PatPepper {
    /// Read the pepper from `NETCIDR_PAT_PEPPER`. The env var must be a
    /// b64url-no-pad encoding of at least [`MIN_PEPPER_BYTES`] bytes.
    pub fn from_env() -> Result<Self> {
        Self::from_env_value(std::env::var(PEPPER_ENV).ok())
    }

    /// Internal helper — separated from [`Self::from_env`] so unit tests
    /// can exercise the unset / empty / short / valid branches without
    /// mutating process environment (Rust 2024 makes `set_var` unsafe).
    pub(crate) fn from_env_value(value: Option<String>) -> Result<Self> {
        let raw = value.unwrap_or_default();
        if raw.is_empty() {
            return Err(NetcidrError::ConfigParse(format!(
                "{PEPPER_ENV} must be set when OIDC auth is enabled"
            )));
        }
        let bytes = URL_SAFE_NO_PAD.decode(raw.as_bytes()).map_err(|e| {
            NetcidrError::ConfigParse(format!("{PEPPER_ENV} is not valid base64url-no-pad: {e}"))
        })?;
        Self::from_bytes(&bytes)
    }

    /// Construct a pepper from already-decoded bytes (test entry point).
    /// Rejects any input shorter than [`MIN_PEPPER_BYTES`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < MIN_PEPPER_BYTES {
            return Err(NetcidrError::ConfigParse(format!(
                "PAT pepper must be at least {MIN_PEPPER_BYTES} bytes (got {})",
                b.len()
            )));
        }
        Ok(Self(b.to_vec().into_boxed_slice()))
    }

    /// Crate-private accessor used by hashing routines.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Output of [`mint`] — contains the one-time plaintext, the public
/// prefix to store/display, and the hash to persist.
///
/// `plaintext` is sensitive: the `Debug` impl redacts it. The `prefix`
/// and `hash` fields are safe to log (prefix is intentionally public;
/// the hash is not the secret — possession of the hash does not yield
/// the plaintext without the pepper *and* a 256-bit search).
pub struct MintedToken {
    pub plaintext: String,
    pub prefix: String,
    pub hash: [u8; 32],
}

impl fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedToken")
            .field("plaintext", &"<redacted>")
            .field("prefix", &self.prefix)
            .field("hash", &self.hash)
            .finish()
    }
}

/// Mint a fresh token. Draws 32 cryptographically random bytes from
/// [`OsRng`], encodes b64url-no-pad, and computes the storage hash.
///
/// The plaintext returned here is the **only** time the secret exists
/// outside the caller's possession; storage retains only the hash.
pub fn mint(pepper: &PatPepper) -> MintedToken {
    let mut secret = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    let encoded = URL_SAFE_NO_PAD.encode(secret);
    debug_assert_eq!(
        encoded.len(),
        43,
        "32 bytes b64url-no-pad is exactly 43 chars"
    );

    let plaintext = format!("ncdr_pat_{encoded}");
    let prefix = plaintext[..PREFIX_LEN].to_string();
    let hash = sha256_with_pepper(plaintext.as_bytes(), pepper.as_slice());

    MintedToken {
        plaintext,
        prefix,
        hash,
    }
}

/// Compute the storage hash for a candidate plaintext, gated on
/// wire-format validity. Returns `None` for shape-invalid inputs so
/// the caller can short-circuit to a generic 401 without a DB query.
///
/// On `Some(_)`, the hash is `sha256(plaintext_utf8 || pepper)`.
pub fn hash_for_lookup(plaintext: &str, pepper: &PatPepper) -> Option<[u8; 32]> {
    if !PAT_SHAPE.is_match(plaintext) {
        return None;
    }
    Some(sha256_with_pepper(plaintext.as_bytes(), pepper.as_slice()))
}

/// `SHA-256(secret || pepper)`. Concatenation rather than HMAC is fine
/// here because the secret is a 256-bit uniform random value; length
/// extension attacks (the usual reason to prefer HMAC) need a known
/// prefix and an attacker who can extend it, neither of which apply.
fn sha256_with_pepper(secret: &[u8], pepper: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(pepper);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_pepper() -> PatPepper {
        PatPepper::from_bytes(&[0xA5u8; 32]).expect("valid test pepper")
    }

    fn other_pepper() -> PatPepper {
        PatPepper::from_bytes(&[0x5Au8; 32]).expect("valid other test pepper")
    }

    #[test]
    fn mint_produces_well_shaped_tokens() {
        let pepper = test_pepper();
        for _ in 0..100 {
            let m = mint(&pepper);
            assert!(
                PAT_SHAPE.is_match(&m.plaintext),
                "plaintext failed shape: {}",
                m.plaintext
            );
            assert_eq!(
                m.plaintext.len(),
                9 + 43,
                "9 prefix chars + 43 b64url chars"
            );
        }
    }

    #[test]
    fn mint_round_trips_through_hash_for_lookup() {
        let pepper = test_pepper();
        for _ in 0..50 {
            let m = mint(&pepper);
            let looked_up = hash_for_lookup(&m.plaintext, &pepper);
            assert_eq!(looked_up, Some(m.hash));
        }
    }

    #[test]
    fn different_peppers_produce_different_hashes() {
        let pa = test_pepper();
        let pb = other_pepper();
        let m = mint(&pa);
        let with_a = hash_for_lookup(&m.plaintext, &pa).expect("shape ok");
        let with_b = hash_for_lookup(&m.plaintext, &pb).expect("shape ok");
        assert_eq!(with_a, m.hash);
        assert_ne!(
            with_a, with_b,
            "swapping the pepper must change the lookup hash"
        );
    }

    #[test]
    fn bad_shapes_return_none_without_panic() {
        let pepper = test_pepper();
        let valid_43: String = "a".repeat(43);
        let cases: Vec<String> = vec![
            String::new(),
            "ncdr_pat_".to_string(),
            "ncdr_pat_short".to_string(),
            "ghp_validlookingbutwrongprefix1234567890123456789012".to_string(),
            format!("ncdr_pat_{valid_43}X"),
            format!("ncdr_pat_{}", "!".repeat(43)),
            format!("NCDR_PAT_{valid_43}"),
        ];
        for bad in cases {
            assert!(
                hash_for_lookup(&bad, &pepper).is_none(),
                "expected None for {bad:?}"
            );
        }
    }

    #[test]
    fn distinct_mints_produce_distinct_hashes() {
        let pepper = test_pepper();
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let m = mint(&pepper);
            assert!(seen.insert(m.hash), "hash collision in 1000 mints");
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn pepper_from_short_bytes_is_error() {
        assert!(PatPepper::from_bytes(&[0u8; 0]).is_err());
        assert!(PatPepper::from_bytes(&[0u8; 15]).is_err());
        assert!(PatPepper::from_bytes(&[0u8; 16]).is_ok());
    }

    #[test]
    fn pepper_from_unset_or_empty_env_is_error() {
        // Exercise the env-decode branch via the pure helper to avoid
        // racy / unsafe `std::env::set_var` in Rust 2024.
        assert!(PatPepper::from_env_value(None).is_err());
        assert!(PatPepper::from_env_value(Some(String::new())).is_err());
    }

    #[test]
    fn pepper_from_invalid_b64_is_error() {
        // Not part of the original test list but trivially exercised
        // alongside the env branch and protects against silent fallback.
        assert!(PatPepper::from_env_value(Some("!!!not_base64!!!".to_string())).is_err());
    }

    #[test]
    fn pepper_from_short_b64_is_error() {
        // 8 bytes b64url-no-pad → "AAAAAAAAAAA" (11 chars); decoded len = 8 < 16.
        let short = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert!(PatPepper::from_env_value(Some(short)).is_err());
    }

    #[test]
    fn pepper_from_valid_b64_env_works() {
        let good = URL_SAFE_NO_PAD.encode([0xC3u8; 32]);
        let p = PatPepper::from_env_value(Some(good)).expect("valid pepper from env");
        assert_eq!(p.as_slice().len(), 32);
    }

    #[test]
    fn prefix_is_exactly_12_chars() {
        let pepper = test_pepper();
        for _ in 0..50 {
            let m = mint(&pepper);
            assert_eq!(m.prefix.len(), PREFIX_LEN);
            assert!(m.prefix.starts_with("ncdr_pat_"));
            assert_eq!(&m.plaintext[..PREFIX_LEN], m.prefix);
        }
    }

    #[test]
    fn pepper_debug_redacts_bytes() {
        let p = test_pepper();
        let s = format!("{p:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("a5"));
        assert!(!s.contains("A5"));
    }

    #[test]
    fn minted_token_debug_redacts_plaintext() {
        let pepper = test_pepper();
        let m = mint(&pepper);
        let s = format!("{m:?}");
        assert!(s.contains("<redacted>"));
        assert!(
            !s.contains(&m.plaintext),
            "plaintext leaked into Debug output"
        );
    }
}
