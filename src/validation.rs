use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{NetcidrError, Result};
use crate::ipam::models::AllocationStatus;

/// Maximum length for CIDR and IP address input strings.
pub const MAX_INPUT_LENGTH: usize = 256;

/// Maximum length for freeform text fields (name, description, owner, etc.).
const MAX_TEXT_FIELD_LENGTH: usize = 1024;

/// Maximum length for identifier fields (UUIDs, resource IDs).
const MAX_IDENTIFIER_LENGTH: usize = 256;

/// Returns true if `s` contains any ASCII control characters or null bytes.
fn has_control_chars(s: &str) -> bool {
    s.bytes()
        .any(|b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
}

/// Returns true if `s` contains path traversal sequences.
fn has_path_traversal(s: &str) -> bool {
    s.contains("..") || s.contains('\0')
}

/// Validate a CIDR string: length, no control chars, valid format (addr/prefix).
pub fn validate_cidr(s: &str) -> Result<()> {
    if s.len() > MAX_INPUT_LENGTH {
        return Err(NetcidrError::InputTooLong {
            length: s.len(),
            limit: MAX_INPUT_LENGTH,
        });
    }

    if has_control_chars(s) {
        return Err(NetcidrError::InvalidInput(
            "CIDR contains control characters".to_string(),
        ));
    }

    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| NetcidrError::InvalidCidr(s.to_string()))?;

    let _prefix: u8 = prefix_str
        .parse()
        .map_err(|_| NetcidrError::InvalidCidr(s.to_string()))?;

    // Must parse as either IPv4 or IPv6
    let is_v4 = addr_str.parse::<Ipv4Addr>().is_ok();
    let is_v6 = addr_str.parse::<Ipv6Addr>().is_ok();

    if !is_v4 && !is_v6 {
        return Err(NetcidrError::InvalidCidr(s.to_string()));
    }

    // Validate prefix range
    if is_v4 {
        validate_prefix_length(_prefix, 4)?;
    } else {
        validate_prefix_length(_prefix, 6)?;
    }

    Ok(())
}

/// Validate an IP address string: length, no control chars, parseable.
pub fn validate_ip_address(s: &str) -> Result<()> {
    if s.len() > MAX_INPUT_LENGTH {
        return Err(NetcidrError::InputTooLong {
            length: s.len(),
            limit: MAX_INPUT_LENGTH,
        });
    }

    if has_control_chars(s) {
        return Err(NetcidrError::InvalidInput(
            "IP address contains control characters".to_string(),
        ));
    }

    let is_v4 = s.parse::<Ipv4Addr>().is_ok();
    let is_v6 = s.parse::<Ipv6Addr>().is_ok();

    if !is_v4 && !is_v6 {
        return Err(NetcidrError::InvalidInput(format!(
            "not a valid IPv4 or IPv6 address: {}",
            s
        )));
    }

    Ok(())
}

/// Maximum total length of a hostname (RFC 1035 §3.1).
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Validate and canonicalize an IP address: returns the parsed address in its
/// canonical string form (e.g. `2001:DB8::1` → `2001:db8::1`, `010.0.0.1`
/// rejected). Use this before storing an IP so equal addresses compare equal.
pub fn normalize_ip_address(s: &str) -> Result<String> {
    validate_ip_address(s)?;
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Ok(v4.to_string());
    }
    let v6 = s
        .parse::<Ipv6Addr>()
        .map_err(|_| NetcidrError::InvalidInput(format!("not a valid IP address: {}", s)))?;
    Ok(v6.to_string())
}

/// Validate and canonicalize a hostname per RFC 1123: total length ≤ 253, each
/// dot-separated label 1–63 chars of `[A-Za-z0-9-]` with no leading/trailing
/// hyphen. Rejects control chars and path traversal. A single trailing dot is
/// stripped and the result is lowercased.
pub fn normalize_hostname(s: &str) -> Result<String> {
    if has_control_chars(s) {
        return Err(NetcidrError::InvalidInput(
            "hostname contains control characters".to_string(),
        ));
    }
    if has_path_traversal(s) {
        return Err(NetcidrError::InvalidInput(
            "hostname contains path traversal sequences".to_string(),
        ));
    }

    // Tolerate a single canonical trailing dot (FQDN root).
    let trimmed = s.strip_suffix('.').unwrap_or(s);

    if trimmed.is_empty() {
        return Err(NetcidrError::InvalidInput(
            "hostname must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_HOSTNAME_LENGTH {
        return Err(NetcidrError::InputTooLong {
            length: trimmed.len(),
            limit: MAX_HOSTNAME_LENGTH,
        });
    }

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(NetcidrError::InvalidInput(format!(
                "hostname label must be 1-63 characters: '{}'",
                label
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(NetcidrError::InvalidInput(format!(
                "hostname label '{}' contains invalid characters (allowed: A-Z a-z 0-9 -)",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NetcidrError::InvalidInput(format!(
                "hostname label '{}' must not start or end with a hyphen",
                label
            )));
        }
    }

    Ok(trimmed.to_ascii_lowercase())
}

/// Validate a hostname without returning the normalized form.
pub fn validate_hostname(s: &str) -> Result<()> {
    normalize_hostname(s).map(|_| ())
}

/// Validate an email address used as a role-assignment key. Intentionally
/// permissive (a single `@` with non-empty local/domain parts), but rejects
/// control chars, path traversal, and oversized input.
pub fn validate_email(s: &str) -> Result<()> {
    if has_control_chars(s) || has_path_traversal(s) {
        return Err(NetcidrError::InvalidInput(
            "email contains invalid characters".to_string(),
        ));
    }
    if s.len() > MAX_HOSTNAME_LENGTH {
        return Err(NetcidrError::InputTooLong {
            length: s.len(),
            limit: MAX_HOSTNAME_LENGTH,
        });
    }
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(NetcidrError::InvalidInput(format!(
            "not a valid email address: {s}"
        )));
    }
    Ok(())
}

/// Validate prefix length for the given IP version (4 or 6).
pub fn validate_prefix_length(prefix: u8, ip_version: u8) -> Result<()> {
    let max = if ip_version == 4 { 32 } else { 128 };
    if prefix > max {
        return Err(NetcidrError::InvalidPrefixLength(prefix));
    }
    Ok(())
}

/// Validate a freeform text field: length limit, reject control chars and null bytes.
pub fn validate_text_field(s: &str, max_len: usize) -> Result<()> {
    let limit = if max_len == 0 {
        MAX_TEXT_FIELD_LENGTH
    } else {
        max_len
    };

    if s.len() > limit {
        return Err(NetcidrError::InputTooLong {
            length: s.len(),
            limit,
        });
    }

    if has_control_chars(s) {
        return Err(NetcidrError::InvalidInput(
            "text field contains control characters".to_string(),
        ));
    }

    Ok(())
}

/// Validate an identifier (UUID, resource ID): reject path traversal, null bytes, control chars.
pub fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(NetcidrError::InvalidInput(
            "identifier cannot be empty".to_string(),
        ));
    }

    if s.len() > MAX_IDENTIFIER_LENGTH {
        return Err(NetcidrError::InputTooLong {
            length: s.len(),
            limit: MAX_IDENTIFIER_LENGTH,
        });
    }

    if has_control_chars(s) {
        return Err(NetcidrError::InvalidInput(
            "identifier contains control characters".to_string(),
        ));
    }

    if has_path_traversal(s) {
        return Err(NetcidrError::InvalidInput(
            "identifier contains path traversal sequence".to_string(),
        ));
    }

    Ok(())
}

/// Validate and parse a status string against the allowlist.
pub fn sanitize_status(s: &str) -> Result<AllocationStatus> {
    match s.to_lowercase().as_str() {
        "active" => Ok(AllocationStatus::Active),
        "reserved" => Ok(AllocationStatus::Reserved),
        "released" => Ok(AllocationStatus::Released),
        _ => Err(NetcidrError::InvalidInput(format!(
            "invalid status '{}': must be one of: active, reserved, released",
            s
        ))),
    }
}

/// Validate an optional text field — passes if None.
pub fn validate_optional_text(field: &Option<String>, max_len: usize) -> Result<()> {
    if let Some(s) = field {
        validate_text_field(s, max_len)?;
    }
    Ok(())
}

/// Validate an optional identifier — passes if None.
pub fn validate_optional_identifier(field: &Option<String>) -> Result<()> {
    if let Some(s) = field {
        validate_identifier(s)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_cidr
    // -----------------------------------------------------------------------

    #[test]
    fn valid_ipv4_cidr() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("0.0.0.0/0").is_ok());
        assert!(validate_cidr("255.255.255.255/32").is_ok());
    }

    #[test]
    fn valid_ipv6_cidr() {
        assert!(validate_cidr("2001:db8::/32").is_ok());
        assert!(validate_cidr("fe80::1/128").is_ok());
        assert!(validate_cidr("::/0").is_ok());
    }

    #[test]
    fn cidr_too_long() {
        let long = format!("{}192.168.1.0/24", "x".repeat(300));
        let err = validate_cidr(&long).unwrap_err();
        assert!(matches!(err, NetcidrError::InputTooLong { .. }));
    }

    #[test]
    fn cidr_with_control_chars() {
        let err = validate_cidr("192.168.1.0\x00/24").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn cidr_missing_slash() {
        let err = validate_cidr("192.168.1.0").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidCidr(_)));
    }

    #[test]
    fn cidr_invalid_prefix() {
        let err = validate_cidr("192.168.1.0/33").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidPrefixLength(33)));
    }

    #[test]
    fn cidr_invalid_address() {
        let err = validate_cidr("999.999.999.999/24").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidCidr(_)));
    }

    #[test]
    fn cidr_non_numeric_prefix() {
        let err = validate_cidr("10.0.0.0/abc").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidCidr(_)));
    }

    #[test]
    fn cidr_empty_string() {
        let err = validate_cidr("").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidCidr(_)));
    }

    // -----------------------------------------------------------------------
    // validate_ip_address
    // -----------------------------------------------------------------------

    #[test]
    fn valid_ipv4_address() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("0.0.0.0").is_ok());
    }

    #[test]
    fn valid_ipv6_address() {
        assert!(validate_ip_address("2001:db8::1").is_ok());
        assert!(validate_ip_address("::1").is_ok());
    }

    #[test]
    fn ip_address_invalid() {
        let err = validate_ip_address("not-an-ip").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn ip_address_too_long() {
        let long = "a".repeat(300);
        let err = validate_ip_address(&long).unwrap_err();
        assert!(matches!(err, NetcidrError::InputTooLong { .. }));
    }

    #[test]
    fn ip_address_with_null_byte() {
        let err = validate_ip_address("10.0.0\x001").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    // -----------------------------------------------------------------------
    // validate_prefix_length
    // -----------------------------------------------------------------------

    #[test]
    fn prefix_v4_valid_range() {
        for p in 0..=32 {
            assert!(validate_prefix_length(p, 4).is_ok());
        }
    }

    #[test]
    fn prefix_v4_out_of_range() {
        let err = validate_prefix_length(33, 4).unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidPrefixLength(33)));
    }

    #[test]
    fn prefix_v6_valid_range() {
        assert!(validate_prefix_length(0, 6).is_ok());
        assert!(validate_prefix_length(64, 6).is_ok());
        assert!(validate_prefix_length(128, 6).is_ok());
    }

    #[test]
    fn prefix_v6_out_of_range() {
        let err = validate_prefix_length(129, 6).unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidPrefixLength(129)));
    }

    // -----------------------------------------------------------------------
    // validate_text_field
    // -----------------------------------------------------------------------

    #[test]
    fn text_field_valid() {
        assert!(validate_text_field("my network", 0).is_ok());
        assert!(validate_text_field("Production VPC", 100).is_ok());
    }

    #[test]
    fn text_field_with_unicode() {
        assert!(validate_text_field("Netzwerk für Produktion", 0).is_ok());
    }

    #[test]
    fn text_field_too_long() {
        let long = "x".repeat(1025);
        let err = validate_text_field(&long, 0).unwrap_err();
        assert!(matches!(err, NetcidrError::InputTooLong { .. }));
    }

    #[test]
    fn text_field_custom_max() {
        let err = validate_text_field("hello", 3).unwrap_err();
        assert!(matches!(err, NetcidrError::InputTooLong { .. }));
    }

    #[test]
    fn text_field_with_control_char() {
        let err = validate_text_field("bad\x01value", 0).unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn text_field_allows_tabs_and_newlines() {
        assert!(validate_text_field("line1\nline2", 0).is_ok());
        assert!(validate_text_field("col1\tcol2", 0).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_identifier
    // -----------------------------------------------------------------------

    #[test]
    fn identifier_valid_uuid() {
        assert!(validate_identifier("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn identifier_valid_simple() {
        assert!(validate_identifier("vpc-12345").is_ok());
    }

    #[test]
    fn identifier_empty() {
        let err = validate_identifier("").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn identifier_with_path_traversal() {
        let err = validate_identifier("../etc/passwd").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn identifier_with_null_byte() {
        let err = validate_identifier("id\x00injected").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn identifier_too_long() {
        let long = "a".repeat(257);
        let err = validate_identifier(&long).unwrap_err();
        assert!(matches!(err, NetcidrError::InputTooLong { .. }));
    }

    #[test]
    fn identifier_with_control_char() {
        let err = validate_identifier("id\x07bell").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    // -----------------------------------------------------------------------
    // sanitize_status
    // -----------------------------------------------------------------------

    #[test]
    fn status_valid_lowercase() {
        assert_eq!(sanitize_status("active").unwrap(), AllocationStatus::Active);
        assert_eq!(
            sanitize_status("reserved").unwrap(),
            AllocationStatus::Reserved
        );
        assert_eq!(
            sanitize_status("released").unwrap(),
            AllocationStatus::Released
        );
    }

    #[test]
    fn status_valid_mixed_case() {
        assert_eq!(sanitize_status("Active").unwrap(), AllocationStatus::Active);
        assert_eq!(
            sanitize_status("RESERVED").unwrap(),
            AllocationStatus::Reserved
        );
    }

    #[test]
    fn status_invalid() {
        let err = sanitize_status("deleted").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    #[test]
    fn status_empty() {
        let err = sanitize_status("").unwrap_err();
        assert!(matches!(err, NetcidrError::InvalidInput(_)));
    }

    // -----------------------------------------------------------------------
    // normalize_hostname / validate_hostname
    // -----------------------------------------------------------------------

    #[test]
    fn hostname_accepts_valid_fqdn() {
        assert_eq!(
            normalize_hostname("Web-01.Example.COM").unwrap(),
            "web-01.example.com"
        );
        assert_eq!(normalize_hostname("host").unwrap(), "host");
        // Trailing FQDN dot is tolerated and stripped.
        assert_eq!(
            normalize_hostname("web-01.example.com.").unwrap(),
            "web-01.example.com"
        );
    }

    #[test]
    fn hostname_rejects_empty() {
        assert!(matches!(
            normalize_hostname(""),
            Err(NetcidrError::InvalidInput(_))
        ));
    }

    #[test]
    fn hostname_rejects_too_long() {
        let long = format!("{}.com", "a".repeat(300));
        assert!(matches!(
            normalize_hostname(&long),
            Err(NetcidrError::InputTooLong { .. })
        ));
    }

    #[test]
    fn hostname_rejects_oversized_label() {
        let label = "a".repeat(64);
        assert!(matches!(
            normalize_hostname(&format!("{label}.com")),
            Err(NetcidrError::InvalidInput(_))
        ));
    }

    #[test]
    fn hostname_rejects_leading_or_trailing_hyphen() {
        assert!(normalize_hostname("-bad.example.com").is_err());
        assert!(normalize_hostname("bad-.example.com").is_err());
    }

    #[test]
    fn hostname_rejects_invalid_chars() {
        assert!(normalize_hostname("under_score.example.com").is_err());
        assert!(normalize_hostname("spa ce.example.com").is_err());
    }

    #[test]
    fn hostname_rejects_control_and_traversal() {
        assert!(normalize_hostname("evil\u{0}.com").is_err());
        assert!(normalize_hostname("../etc/passwd").is_err());
    }

    // -----------------------------------------------------------------------
    // normalize_ip_address
    // -----------------------------------------------------------------------

    #[test]
    fn ip_normalizes_canonical_form() {
        assert_eq!(normalize_ip_address("10.0.0.5").unwrap(), "10.0.0.5");
        assert_eq!(
            normalize_ip_address("2001:DB8::0001").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn ip_rejects_garbage() {
        assert!(normalize_ip_address("not-an-ip").is_err());
    }
}
