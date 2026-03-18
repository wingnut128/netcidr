use crate::error::{IpCalcError, Result};
use crate::ipv4::Ipv4Subnet;
use crate::ipv6::Ipv6Subnet;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Result structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv4SummaryResult {
    pub input_count: usize,
    pub output_count: usize,
    pub cidrs: Vec<Ipv4Subnet>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv6SummaryResult {
    pub input_count: usize,
    pub output_count: usize,
    pub cidrs: Vec<Ipv6Subnet>,
}

// ---------------------------------------------------------------------------
// Generic summarization algorithm over (network, prefix) pairs
// ---------------------------------------------------------------------------

/// Compute a u128 mask for a given prefix, accounting for address family bit width.
/// For IPv4 (bits=32), computes via u32 then extends; for IPv6 (bits=128), computes directly.
fn prefix_mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0u128
    } else if bits == 32 {
        (crate::ipv4::ipv4_mask(prefix)) as u128
    } else {
        crate::ipv6::ipv6_mask(prefix)
    }
}

fn normalize_and_sort(entries: &mut Vec<(u128, u8)>, bits: u8) {
    // Normalize: zero host bits
    for entry in entries.iter_mut() {
        entry.0 &= prefix_mask(entry.1, bits);
    }

    // Sort by (network asc, prefix asc)
    entries.sort();

    // Dedup exact duplicates
    entries.dedup();
}

fn remove_contained(entries: &mut Vec<(u128, u8)>, bits: u8) {
    if entries.is_empty() {
        return;
    }

    let mut kept: Vec<(u128, u8)> = Vec::with_capacity(entries.len());
    kept.push(entries[0]);

    for &entry in &entries[1..] {
        let last = kept.last().unwrap();
        // Check if entry is contained in last kept entry
        let mask = prefix_mask(last.1, bits);

        if entry.1 >= last.1 && (entry.0 & mask) == last.0 {
            // entry is contained in last, skip
            continue;
        }
        kept.push(entry);
    }

    *entries = kept;
}

fn merge_siblings(entries: &mut Vec<(u128, u8)>, bits: u8) {
    loop {
        let mut merged = false;
        let mut result: Vec<(u128, u8)> = Vec::with_capacity(entries.len());
        let mut i = 0;

        while i < entries.len() {
            if i + 1 < entries.len() {
                let (net_a, pfx_a) = entries[i];
                let (net_b, pfx_b) = entries[i + 1];

                if pfx_a == pfx_b && pfx_a > 0 {
                    let parent_prefix = pfx_a - 1;
                    let shift = bits - parent_prefix;

                    let parent_a = if shift >= 128 { 0 } else { net_a >> shift };
                    let parent_b = if shift >= 128 { 0 } else { net_b >> shift };

                    if parent_a == parent_b {
                        // Merge into parent
                        result.push((net_a & prefix_mask(parent_prefix, bits), parent_prefix));
                        merged = true;
                        i += 2;
                        continue;
                    }
                }
            }
            result.push(entries[i]);
            i += 1;
        }

        *entries = result;

        if !merged {
            break;
        }

        // After merging, we may have new containment or new siblings, so re-sort and re-clean
        entries.sort();
        entries.dedup();
        remove_contained(entries, bits);
    }
}

fn summarize_entries(entries: &mut Vec<(u128, u8)>, bits: u8) {
    if entries.is_empty() {
        return;
    }
    normalize_and_sort(entries, bits);
    remove_contained(entries, bits);
    merge_siblings(entries, bits);
}

pub const DEFAULT_MAX_SUMMARIZE_INPUTS: usize = 10_000;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Validate inputs and run the summarization algorithm, returning raw (network, prefix) pairs.
fn validate_and_summarize(
    cidrs: &[String],
    max_inputs: usize,
    bits: u8,
    parse: impl Fn(&str) -> Result<(u128, u8)>,
) -> Result<(usize, Vec<(u128, u8)>)> {
    if cidrs.is_empty() {
        return Err(IpCalcError::EmptyCidrList);
    }
    if cidrs.len() > max_inputs {
        return Err(IpCalcError::SummarizeInputLimitExceeded {
            count: cidrs.len(),
            limit: max_inputs,
        });
    }

    let input_count = cidrs.len();
    let mut entries: Vec<(u128, u8)> = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        entries.push(parse(cidr)?);
    }

    summarize_entries(&mut entries, bits);
    Ok((input_count, entries))
}

pub fn summarize_ipv4(cidrs: &[String]) -> Result<Ipv4SummaryResult> {
    summarize_ipv4_with_limit(cidrs, DEFAULT_MAX_SUMMARIZE_INPUTS)
}

pub fn summarize_ipv4_with_limit(cidrs: &[String], max_inputs: usize) -> Result<Ipv4SummaryResult> {
    let (input_count, entries) = validate_and_summarize(cidrs, max_inputs, 32, |cidr| {
        let subnet = Ipv4Subnet::from_cidr(cidr)?;
        Ok((u32::from(subnet.network) as u128, subnet.prefix_length))
    })?;

    let mut result_cidrs = Vec::with_capacity(entries.len());
    for (network, prefix) in &entries {
        let addr = Ipv4Addr::from(*network as u32);
        result_cidrs.push(Ipv4Subnet::new(addr, *prefix)?);
    }

    Ok(Ipv4SummaryResult {
        input_count,
        output_count: result_cidrs.len(),
        cidrs: result_cidrs,
    })
}

pub fn summarize_ipv6(cidrs: &[String]) -> Result<Ipv6SummaryResult> {
    summarize_ipv6_with_limit(cidrs, DEFAULT_MAX_SUMMARIZE_INPUTS)
}

pub fn summarize_ipv6_with_limit(cidrs: &[String], max_inputs: usize) -> Result<Ipv6SummaryResult> {
    let (input_count, entries) = validate_and_summarize(cidrs, max_inputs, 128, |cidr| {
        let subnet = Ipv6Subnet::from_cidr(cidr)?;
        Ok((u128::from(subnet.network), subnet.prefix_length))
    })?;

    let mut result_cidrs = Vec::with_capacity(entries.len());
    for (network, prefix) in &entries {
        let addr = Ipv6Addr::from(*network);
        result_cidrs.push(Ipv6Subnet::new(addr, *prefix)?);
    }

    Ok(Ipv6SummaryResult {
        input_count,
        output_count: result_cidrs.len(),
        cidrs: result_cidrs,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_adjacent_merge_ipv4() {
        let result =
            summarize_ipv4(&["192.168.0.0/24".to_string(), "192.168.1.0/24".to_string()]).unwrap();
        assert_eq!(result.input_count, 2);
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 23);
    }

    #[test]
    fn test_containment_collapse() {
        let result =
            summarize_ipv4(&["10.0.0.0/8".to_string(), "10.1.0.0/16".to_string()]).unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 8);
    }

    #[test]
    fn test_cascade_merge() {
        // 4x /24 → /22
        let result = summarize_ipv4(&[
            "10.0.0.0/24".to_string(),
            "10.0.1.0/24".to_string(),
            "10.0.2.0/24".to_string(),
            "10.0.3.0/24".to_string(),
        ])
        .unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 22);
    }

    #[test]
    fn test_duplicates() {
        let result =
            summarize_ipv4(&["192.168.1.0/24".to_string(), "192.168.1.0/24".to_string()]).unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(result.cidrs[0].prefix_length, 24);
    }

    #[test]
    fn test_single_input() {
        let result = summarize_ipv4(&["172.16.0.0/12".to_string()]).unwrap();
        assert_eq!(result.input_count, 1);
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 12);
    }

    #[test]
    fn test_non_normalized_input() {
        // 192.168.1.50/24 should normalize to 192.168.1.0/24
        let result = summarize_ipv4(&[
            "192.168.0.50/24".to_string(),
            "192.168.1.100/24".to_string(),
        ])
        .unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].network, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(result.cidrs[0].prefix_length, 23);
    }

    #[test]
    fn test_prefix_zero() {
        let result = summarize_ipv4(&["0.0.0.0/0".to_string()]).unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(result.cidrs[0].prefix_length, 0);
    }

    #[test]
    fn test_non_adjacent_no_merge() {
        let result =
            summarize_ipv4(&["10.0.0.0/24".to_string(), "10.0.2.0/24".to_string()]).unwrap();
        assert_eq!(result.output_count, 2);
    }

    #[test]
    fn test_ipv6_adjacent_merge() {
        let result =
            summarize_ipv6(&["2001:db8::/48".to_string(), "2001:db8:1::/48".to_string()]).unwrap();
        assert_eq!(result.input_count, 2);
        assert_eq!(result.output_count, 1);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::").unwrap()
        );
        assert_eq!(result.cidrs[0].prefix_length, 47);
    }

    // -----------------------------------------------------------------------
    // IPv6 test cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_ipv6_adjacent_64s_merge_to_63() {
        let result = summarize_ipv6(&[
            "2001:db8:1:0::/64".to_string(),
            "2001:db8:1:1::/64".to_string(),
        ])
        .unwrap();
        assert_eq!(result.input_count, 2);
        assert_eq!(result.output_count, 1);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8:1::").unwrap()
        );
        assert_eq!(result.cidrs[0].prefix_length, 63);
    }

    #[test]
    fn test_ipv6_containment_collapse() {
        // /48 contains the /64, should collapse to the /48
        let result = summarize_ipv6(&[
            "2001:db8:abcd::/48".to_string(),
            "2001:db8:abcd:1::/64".to_string(),
        ])
        .unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8:abcd::").unwrap()
        );
        assert_eq!(result.cidrs[0].prefix_length, 48);
    }

    #[test]
    fn test_ipv6_duplicate_cidrs() {
        let result =
            summarize_ipv6(&["2001:db8::/32".to_string(), "2001:db8::/32".to_string()]).unwrap();
        assert_eq!(result.input_count, 2);
        assert_eq!(result.output_count, 1);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::").unwrap()
        );
        assert_eq!(result.cidrs[0].prefix_length, 32);
    }

    #[test]
    fn test_ipv6_non_adjacent_no_merge() {
        // These /64s are not siblings (differ in bit 62), so they should not merge
        let result = summarize_ipv6(&[
            "2001:db8:1:0::/64".to_string(),
            "2001:db8:1:2::/64".to_string(),
        ])
        .unwrap();
        assert_eq!(result.output_count, 2);
    }

    #[test]
    fn test_ipv6_non_normalized_input() {
        // 2001:db8::1/32 has host bits set; should normalize to 2001:db8::/32
        let result = summarize_ipv6(&["2001:db8::1/32".to_string()]).unwrap();
        assert_eq!(result.output_count, 1);
        assert_eq!(
            result.cidrs[0].network,
            Ipv6Addr::from_str("2001:db8::").unwrap()
        );
        assert_eq!(result.cidrs[0].prefix_length, 32);
    }

    #[test]
    fn test_mixed_ipv6_in_ipv4_summarize_errors() {
        // Passing an IPv6 CIDR to summarize_ipv4 should produce an error
        let result = summarize_ipv4(&["192.168.0.0/24".to_string(), "2001:db8::/32".to_string()]);
        assert!(
            result.is_err(),
            "expected error for mixed input, got {:?}",
            result
        );
    }

    #[test]
    fn test_mixed_ipv4_in_ipv6_summarize_errors() {
        // Passing an IPv4 CIDR to summarize_ipv6 should produce an error
        let result = summarize_ipv6(&["2001:db8::/32".to_string(), "192.168.0.0/24".to_string()]);
        assert!(
            result.is_err(),
            "expected error for mixed input, got {:?}",
            result
        );
    }

    #[test]
    fn test_empty_input() {
        let result = summarize_ipv4(&[]);
        assert!(
            matches!(result, Err(IpCalcError::EmptyCidrList)),
            "expected EmptyCidrList, got {:?}",
            result
        );
    }

    #[test]
    fn test_summarize_input_limit_exceeded() {
        let cidrs: Vec<String> = (0..5).map(|i| format!("10.{}.0.0/16", i)).collect();
        let result = summarize_ipv4_with_limit(&cidrs, 3);
        assert!(
            matches!(
                result,
                Err(IpCalcError::SummarizeInputLimitExceeded { count: 5, limit: 3 })
            ),
            "expected SummarizeInputLimitExceeded, got {:?}",
            result
        );
    }
}
