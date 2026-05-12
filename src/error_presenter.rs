//! Single point where a [`NetcidrError`] becomes a caller-visible
//! response. Every frontend — IPAM HTTP API, `/me/tokens` HTTP API,
//! MCP tool results — passes its errors through [`present`] so the
//! status code, scrubbed client message, and logging policy live in
//! one place.
//!
//! See the `Error Presenter` and `Presented Error` entries in
//! `CONTEXT.md`.

use crate::error::NetcidrError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Frontend should not log; the caller is responsible for handling
    /// their own bad input. Used for 4xx classes.
    None,
    /// Frontend should emit `tracing::error!` with the original `err`
    /// before responding. Used for 5xx classes and unrecognized
    /// variants, where the operator needs the full unscrubbed message
    /// to diagnose.
    Error,
}

/// Wire-format-neutral view of a [`NetcidrError`]. HTTP frontends
/// serialize it to `{ "error": client_msg }` with `status`; the MCP
/// frontend renders it as a scrubbed string. `client_msg` is always
/// safe to expose — raw database, transport, and unrecognized errors
/// are flattened to `"internal server error"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedError {
    pub status: u16,
    pub client_msg: String,
    pub log_level: LogLevel,
}

/// Translate a [`NetcidrError`] into the canonical [`PresentedError`].
///
/// Policy:
/// - All validation / shape variants → 400, message passes through `Display`.
/// - Domain "not found" variants → 404; `PatNotFound` is canonicalised
///   to `"token not found"` so the caller-supplied id is never echoed back.
/// - Conflict variants → 409, message passes through.
/// - `NoFreeSpace` → 422, message passes through.
/// - `Upstream { status, message }` → that exact status and message
///   (the upstream has already scrubbed and classified).
/// - `DatabaseError`, `Io`, `Json`, `Csv`, `Yaml`, `ConfigParse`, and
///   any future variant → 500 `"internal server error"`, log at error.
pub fn present(err: &NetcidrError) -> PresentedError {
    use NetcidrError::*;

    match err {
        // 400 — validation / input shape
        InvalidIpv4Address(_)
        | InvalidIpv6Address(_)
        | InvalidCidr(_)
        | InvalidPrefixLength(_)
        | InvalidInput(_)
        | InvalidSubnetSplit { .. }
        | InvalidRange(_, _)
        | EmptyCidrList
        | InsufficientSubnets { .. }
        | SubnetLimitExceeded { .. }
        | BatchSizeExceeded { .. }
        | FromRangeLimitExceeded { .. }
        | SummarizeInputLimitExceeded { .. }
        | InputTooLong { .. } => PresentedError {
            status: 400,
            client_msg: err.to_string(),
            log_level: LogLevel::None,
        },

        // 404 — domain "not found"
        CidrBlockNotFound(_) | AllocationNotFound(_) => PresentedError {
            status: 404,
            client_msg: err.to_string(),
            log_level: LogLevel::None,
        },

        // 404 — PAT not found; do NOT echo the caller-supplied id.
        PatNotFound(_) => PresentedError {
            status: 404,
            client_msg: "token not found".to_string(),
            log_level: LogLevel::None,
        },

        // 409 — conflict
        AllocationConflict { .. } | CidrBlockHasActiveAllocations(_) => PresentedError {
            status: 409,
            client_msg: err.to_string(),
            log_level: LogLevel::None,
        },

        // 422 — domain rule violated by an otherwise-valid request
        NoFreeSpace { .. } => PresentedError {
            status: 422,
            client_msg: err.to_string(),
            log_level: LogLevel::None,
        },

        // Passthrough from an upstream API (HTTP-client adapters set
        // this variant after the upstream's presenter ran). Trust the
        // upstream's status; log 5xx classes at error so an operator
        // notices repeated upstream failures.
        Upstream { status, message } => PresentedError {
            status: *status,
            client_msg: message.clone(),
            log_level: if *status >= 500 {
                LogLevel::Error
            } else {
                LogLevel::None
            },
        },

        // 500 — never expose raw text. DB driver messages, IO/serde
        // failures, and anything we forgot to classify all collapse here.
        DatabaseError(_) | Io(_) | Json(_) | Csv(_) | Yaml(_) | ConfigParse(_) => PresentedError {
            status: 500,
            client_msg: "internal server error".to_string(),
            log_level: LogLevel::Error,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(err: NetcidrError, status: u16, msg: &str, log: LogLevel) {
        let p = present(&err);
        assert_eq!(
            p,
            PresentedError {
                status,
                client_msg: msg.to_string(),
                log_level: log,
            },
            "variant {err:?} presented incorrectly",
        );
    }

    #[test]
    fn validation_variants_are_400_and_passthrough() {
        case(
            NetcidrError::InvalidIpv4Address("1.2.3".into()),
            400,
            "Invalid IPv4 address: 1.2.3",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidIpv6Address("::xyz".into()),
            400,
            "Invalid IPv6 address: ::xyz",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidCidr("nope".into()),
            400,
            "Invalid CIDR notation: nope",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidPrefixLength(99),
            400,
            "Invalid prefix length: 99 (must be 0-32 for IPv4, 0-128 for IPv6)",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidInput("bad".into()),
            400,
            "Invalid input: bad",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidSubnetSplit {
                new_prefix: 16,
                original_prefix: 24,
            },
            400,
            "New prefix length 16 must be greater than original prefix 24",
            LogLevel::None,
        );
        case(
            NetcidrError::InvalidRange("10.0.0.5".into(), "10.0.0.1".into()),
            400,
            "Invalid range: start 10.0.0.5 is greater than end 10.0.0.1",
            LogLevel::None,
        );
        case(
            NetcidrError::EmptyCidrList,
            400,
            "No CIDRs provided for summarization",
            LogLevel::None,
        );
    }

    #[test]
    fn limit_variants_are_400() {
        case(
            NetcidrError::InsufficientSubnets {
                requested: 10,
                available: 4,
                new_prefix: 24,
                original_prefix: 22,
            },
            400,
            "Cannot generate 10 /24 subnets from /22 (only 4 available)",
            LogLevel::None,
        );
        case(
            NetcidrError::SubnetLimitExceeded {
                count: "1000".into(),
                limit: 100,
            },
            400,
            "Generating 1000 subnets exceeds the limit of 100. Use --count-only to see the count, or -n to generate a smaller number.",
            LogLevel::None,
        );
        case(
            NetcidrError::BatchSizeExceeded {
                count: 5000,
                limit: 1000,
            },
            400,
            "Batch size 5000 exceeds maximum of 1000",
            LogLevel::None,
        );
        case(
            NetcidrError::FromRangeLimitExceeded {
                count: 9000,
                limit: 1000,
            },
            400,
            "Generated CIDR count 9000 exceeds maximum of 1000",
            LogLevel::None,
        );
        case(
            NetcidrError::SummarizeInputLimitExceeded {
                count: 9000,
                limit: 1000,
            },
            400,
            "Summarize input count 9000 exceeds maximum of 1000",
            LogLevel::None,
        );
        case(
            NetcidrError::InputTooLong {
                length: 2048,
                limit: 1024,
            },
            400,
            "Input string exceeds maximum length of 1024 bytes",
            LogLevel::None,
        );
    }

    #[test]
    fn not_found_variants_are_404() {
        case(
            NetcidrError::CidrBlockNotFound("abc".into()),
            404,
            "CIDR block not found: abc",
            LogLevel::None,
        );
        case(
            NetcidrError::AllocationNotFound("def".into()),
            404,
            "Allocation not found: def",
            LogLevel::None,
        );
    }

    #[test]
    fn pat_not_found_is_scrubbed() {
        case(
            NetcidrError::PatNotFound("pat_secret_id_123".into()),
            404,
            "token not found",
            LogLevel::None,
        );
    }

    #[test]
    fn conflict_variants_are_409() {
        case(
            NetcidrError::AllocationConflict {
                existing: "10.0.0.0/24".into(),
                candidate: "10.0.0.0/16".into(),
            },
            409,
            "Allocation conflict: 10.0.0.0/16 overlaps with existing 10.0.0.0/24",
            LogLevel::None,
        );
        case(
            NetcidrError::CidrBlockHasActiveAllocations("sn1".into()),
            409,
            "CIDR block sn1 has active allocations and cannot be deleted",
            LogLevel::None,
        );
    }

    #[test]
    fn no_free_space_is_422() {
        case(
            NetcidrError::NoFreeSpace {
                cidr_block: "10.0.0.0/24".into(),
                prefix: 28,
            },
            422,
            "No free space in 10.0.0.0/24 for a /28 allocation",
            LogLevel::None,
        );
    }

    #[test]
    fn upstream_passes_status_and_message_through() {
        case(
            NetcidrError::Upstream {
                status: 409,
                message: "allocation conflict".into(),
            },
            409,
            "allocation conflict",
            LogLevel::None,
        );
        case(
            NetcidrError::Upstream {
                status: 401,
                message: "missing bearer".into(),
            },
            401,
            "missing bearer",
            LogLevel::None,
        );
        // 5xx upstreams are surfaced as 5xx and logged so the operator
        // sees repeated upstream failures.
        case(
            NetcidrError::Upstream {
                status: 503,
                message: "upstream unavailable".into(),
            },
            503,
            "upstream unavailable",
            LogLevel::Error,
        );
    }

    #[test]
    fn database_error_is_scrubbed_to_500() {
        // Even if the raw message contains "overlap" or "not found"
        // (legacy substring shim) it is NOT classified — it goes to 500.
        case(
            NetcidrError::DatabaseError(
                "UNIQUE constraint failed: allocations.cidr; range overlaps".into(),
            ),
            500,
            "internal server error",
            LogLevel::Error,
        );
        case(
            NetcidrError::DatabaseError("PostgreSQL connection failed".into()),
            500,
            "internal server error",
            LogLevel::Error,
        );
    }

    #[test]
    fn infrastructure_errors_are_scrubbed_to_500() {
        case(
            NetcidrError::Io(std::io::Error::other("disk gone")),
            500,
            "internal server error",
            LogLevel::Error,
        );
        case(
            NetcidrError::Csv("bad csv".into()),
            500,
            "internal server error",
            LogLevel::Error,
        );
        case(
            NetcidrError::Yaml("bad yaml".into()),
            500,
            "internal server error",
            LogLevel::Error,
        );
        case(
            NetcidrError::ConfigParse("missing key".into()),
            500,
            "internal server error",
            LogLevel::Error,
        );
        // Json error — synthesize via a deliberate parse failure
        let json_err: serde_json::Error = serde_json::from_str::<u32>("not a number").unwrap_err();
        case(
            NetcidrError::Json(json_err),
            500,
            "internal server error",
            LogLevel::Error,
        );
    }

    /// Compile-time guard: every `NetcidrError` variant has a presenter
    /// arm. Adding a new variant without updating `present` produces a
    /// non-exhaustive-match error here.
    #[test]
    fn every_variant_is_explicit_in_presenter() {
        // No assertion needed — this test exists so reviewers see the
        // exhaustive match in `present` is the source of truth. If a
        // new variant slips in without an arm, `present` itself fails
        // to compile (no `_ =>` catch-all).
    }
}
