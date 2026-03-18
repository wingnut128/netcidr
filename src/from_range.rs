use crate::error::{IpCalcError, Result};
use crate::ipv4::Ipv4Subnet;
use crate::ipv6::Ipv6Subnet;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Result structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv4FromRangeResult {
    pub start_address: String,
    pub end_address: String,
    pub cidr_count: usize,
    pub cidrs: Vec<Ipv4Subnet>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv6FromRangeResult {
    pub start_address: String,
    pub end_address: String,
    pub cidr_count: usize,
    pub cidrs: Vec<Ipv6Subnet>,
}

pub const DEFAULT_MAX_GENERATED_CIDRS: usize = 1_000_000;

// ---------------------------------------------------------------------------
// Core algorithms
// ---------------------------------------------------------------------------

fn range_to_cidrs_v4(start: u32, end: u32, limit: usize) -> Vec<(u32, u8)> {
    let mut result = Vec::new();
    let mut current = start;
    while current <= end {
        if result.len() > limit {
            break;
        }
        let max_bits = if current == 0 {
            32
        } else {
            current.trailing_zeros()
        };
        let range_size = (end as u64) - (current as u64) + 1;
        let range_bits = range_size.ilog2();
        let bits = max_bits.min(range_bits);
        let prefix = 32 - bits as u8;
        result.push((current, prefix));
        // Advance past this block
        let block_size = 1u64 << bits;
        let next = current as u64 + block_size;
        if next > u32::MAX as u64 {
            break;
        }
        current = next as u32;
    }
    result
}

fn range_to_cidrs_v6(start: u128, end: u128, limit: usize) -> Vec<(u128, u8)> {
    let mut result = Vec::new();
    let mut current = start;
    while current <= end {
        if result.len() > limit {
            break;
        }
        let max_bits = if current == 0 {
            128
        } else {
            current.trailing_zeros()
        };
        let range_size = end - current + 1;
        let range_bits = if range_size == 0 {
            128
        } else {
            range_size.ilog2()
        };
        let bits = max_bits.min(range_bits);
        let prefix = 128 - bits as u8;
        result.push((current, prefix));
        let block_size: u128 = 1u128 << bits;
        let next = current.checked_add(block_size);
        match next {
            Some(n) => current = n,
            None => break,
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn from_range_ipv4(start: &str, end: &str) -> Result<Ipv4FromRangeResult> {
    from_range_ipv4_with_limit(start, end, DEFAULT_MAX_GENERATED_CIDRS)
}

pub fn from_range_ipv4_with_limit(
    start: &str,
    end: &str,
    max_cidrs: usize,
) -> Result<Ipv4FromRangeResult> {
    let start_addr = Ipv4Addr::from_str(start)
        .map_err(|_| IpCalcError::InvalidIpv4Address(start.to_string()))?;
    let end_addr =
        Ipv4Addr::from_str(end).map_err(|_| IpCalcError::InvalidIpv4Address(end.to_string()))?;

    let start_u32 = u32::from(start_addr);
    let end_u32 = u32::from(end_addr);

    if start_u32 > end_u32 {
        return Err(IpCalcError::InvalidRange(
            start.to_string(),
            end.to_string(),
        ));
    }

    let pairs = range_to_cidrs_v4(start_u32, end_u32, max_cidrs);
    if pairs.len() > max_cidrs {
        return Err(IpCalcError::FromRangeLimitExceeded {
            count: pairs.len(),
            limit: max_cidrs,
        });
    }

    let mut cidrs = Vec::with_capacity(pairs.len());
    for (network, prefix) in &pairs {
        let addr = Ipv4Addr::from(*network);
        cidrs.push(Ipv4Subnet::new(addr, *prefix)?);
    }

    Ok(Ipv4FromRangeResult {
        start_address: start_addr.to_string(),
        end_address: end_addr.to_string(),
        cidr_count: cidrs.len(),
        cidrs,
    })
}

pub fn from_range_ipv6(start: &str, end: &str) -> Result<Ipv6FromRangeResult> {
    from_range_ipv6_with_limit(start, end, DEFAULT_MAX_GENERATED_CIDRS)
}

pub fn from_range_ipv6_with_limit(
    start: &str,
    end: &str,
    max_cidrs: usize,
) -> Result<Ipv6FromRangeResult> {
    let start_addr = Ipv6Addr::from_str(start)
        .map_err(|_| IpCalcError::InvalidIpv6Address(start.to_string()))?;
    let end_addr =
        Ipv6Addr::from_str(end).map_err(|_| IpCalcError::InvalidIpv6Address(end.to_string()))?;

    let start_u128 = u128::from(start_addr);
    let end_u128 = u128::from(end_addr);

    if start_u128 > end_u128 {
        return Err(IpCalcError::InvalidRange(
            start.to_string(),
            end.to_string(),
        ));
    }

    let pairs = range_to_cidrs_v6(start_u128, end_u128, max_cidrs);
    if pairs.len() > max_cidrs {
        return Err(IpCalcError::FromRangeLimitExceeded {
            count: pairs.len(),
            limit: max_cidrs,
        });
    }

    let mut cidrs = Vec::with_capacity(pairs.len());
    for (network, prefix) in &pairs {
        let addr = Ipv6Addr::from(*network);
        cidrs.push(Ipv6Subnet::new(addr, *prefix)?);
    }

    Ok(Ipv6FromRangeResult {
        start_address: start_addr.to_string(),
        end_address: end_addr.to_string(),
        cidr_count: cidrs.len(),
        cidrs,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_address_v4() {
        let result = from_range_ipv4("192.168.1.1", "192.168.1.1").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(result.cidrs[0].prefix_length, 32);
    }

    #[test]
    fn test_two_addresses_v4() {
        let result = from_range_ipv4("192.168.1.0", "192.168.1.1").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(result.cidrs[0].prefix_length, 31);
    }

    #[test]
    fn test_full_subnet_v4() {
        let result = from_range_ipv4("10.0.0.0", "10.0.0.255").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 24);
    }

    #[test]
    fn test_non_aligned_range_v4() {
        // 192.168.1.10 - 192.168.1.20 should produce multiple CIDRs
        let result = from_range_ipv4("192.168.1.10", "192.168.1.20").unwrap();
        assert!(result.cidr_count > 1);
        // Verify coverage: first starts at .10, last ends at .20
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 1, 10));
        let last = result.cidrs.last().unwrap();
        // Last CIDR should end at .20
        assert_eq!(last.broadcast, Ipv4Addr::new(192, 168, 1, 20));
    }

    #[test]
    fn test_start_greater_than_end_v4() {
        let result = from_range_ipv4("192.168.1.20", "192.168.1.10");
        assert!(
            matches!(result, Err(IpCalcError::InvalidRange(_, _))),
            "expected InvalidRange, got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_address_v4() {
        let result = from_range_ipv4("not-an-ip", "192.168.1.10");
        assert!(
            matches!(result, Err(IpCalcError::InvalidIpv4Address(_))),
            "expected InvalidIpv4Address, got {:?}",
            result
        );
    }

    #[test]
    fn test_single_address_v6() {
        let result = from_range_ipv6("2001:db8::1", "2001:db8::1").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 128);
    }

    #[test]
    fn test_range_v6() {
        let result = from_range_ipv6("2001:db8::1", "2001:db8::ff").unwrap();
        assert!(result.cidr_count > 1);
        assert_eq!(result.start_address, "2001:db8::1");
        assert_eq!(result.end_address, "2001:db8::ff");
    }

    #[test]
    fn test_aligned_v6() {
        let result = from_range_ipv6("2001:db8::", "2001:db8::ffff").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 112);
    }

    #[test]
    fn test_start_greater_than_end_v6() {
        let result = from_range_ipv6("2001:db8::ff", "2001:db8::1");
        assert!(
            matches!(result, Err(IpCalcError::InvalidRange(_, _))),
            "expected InvalidRange, got {:?}",
            result
        );
    }

    #[test]
    fn test_full_range_v4() {
        // 0.0.0.0 - 255.255.255.255 should be a single /0
        let result = from_range_ipv4("0.0.0.0", "255.255.255.255").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 0);
    }

    #[test]
    fn test_from_range_limit_exceeded_v4() {
        // A range that generates many CIDRs, limited to 2
        let result = from_range_ipv4_with_limit("192.168.1.1", "192.168.1.20", 2);
        assert!(
            matches!(
                result,
                Err(IpCalcError::FromRangeLimitExceeded { limit: 2, .. })
            ),
            "expected FromRangeLimitExceeded, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // IPv6 test cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_address_v6_start_eq_end() {
        let result = from_range_ipv6("2001:db8::abcd", "2001:db8::abcd").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 128);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::abcd").unwrap()
        );
    }

    #[test]
    fn test_two_adjacent_addresses_v6() {
        let result = from_range_ipv6("2001:db8::0", "2001:db8::1").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 127);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::").unwrap()
        );
    }

    #[test]
    fn test_full_64_aligned_range_v6() {
        // A full /64 range: 2001:db8:1:: to 2001:db8:1::ffff:ffff:ffff:ffff
        let result = from_range_ipv6("2001:db8:1::", "2001:db8:1:0:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 64);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8:1::").unwrap()
        );
    }

    #[test]
    fn test_non_aligned_range_v6() {
        // 2001:db8::1 to 2001:db8::6 is non-aligned, requires multiple CIDRs
        let result = from_range_ipv6("2001:db8::1", "2001:db8::6").unwrap();
        assert!(
            result.cidr_count > 1,
            "expected multiple CIDRs, got {}",
            result.cidr_count
        );
        // Verify first CIDR starts at ::1
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::1").unwrap()
        );
        // Verify last CIDR ends at ::6
        assert_eq!(
            result.cidrs.last().unwrap().last,
            Ipv6Addr::from_str("2001:db8::6").unwrap()
        );
    }

    #[test]
    fn test_large_48_range_v6() {
        // A full /48 range
        let result =
            from_range_ipv6("2001:db8:abcd::", "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(result.cidr_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 48);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8:abcd::").unwrap()
        );
    }

    #[test]
    fn test_reversed_range_v6() {
        let result = from_range_ipv6("2001:db8::ffff", "2001:db8::1");
        assert!(
            matches!(result, Err(IpCalcError::InvalidRange(_, _))),
            "expected InvalidRange, got {:?}",
            result
        );
    }

    #[test]
    fn test_algorithm_correctness_v6() {
        // Verify CIDRs exactly cover the range with no gaps
        let result = from_range_ipv6("2001:db8::5", "2001:db8::130").unwrap();
        let start_u128 = u128::from(Ipv6Addr::from_str("2001:db8::5").unwrap());
        let end_u128 = u128::from(Ipv6Addr::from_str("2001:db8::130").unwrap());
        let mut expected_next = start_u128;
        for cidr in &result.cidrs {
            let net = u128::from(cidr.network);
            assert_eq!(net, expected_next, "Gap in CIDR coverage");
            let block_size: u128 = 1u128 << (128 - cidr.prefix_length);
            expected_next = net + block_size;
        }
        assert_eq!(expected_next, end_u128 + 1, "CIDRs don't cover full range");
    }

    #[test]
    fn test_algorithm_correctness_v4() {
        // Verify that the CIDRs exactly cover the range with no gaps/overlaps
        let result = from_range_ipv4("10.0.0.5", "10.0.0.130").unwrap();
        let mut expected_next: u64 = u32::from(Ipv4Addr::from_str("10.0.0.5").unwrap()) as u64;
        for cidr in &result.cidrs {
            let net = u32::from(cidr.network) as u64;
            assert_eq!(net, expected_next, "Gap in CIDR coverage");
            expected_next = net + cidr.total_hosts;
        }
        assert_eq!(
            expected_next,
            u32::from(Ipv4Addr::from_str("10.0.0.130").unwrap()) as u64 + 1,
            "CIDRs don't cover full range"
        );
    }
}
