use crate::error::{NetcidrError, Result};
use crate::ipv4::{Ipv4Subnet, ipv4_mask};
use crate::ipv6::{Ipv6Subnet, ipv6_mask};
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Result of checking whether an IP address falls within a CIDR range.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ContainsResult {
    /// The normalized CIDR that was tested.
    pub cidr: String,
    /// The IP address that was tested.
    pub address: String,
    /// `true` if the address is inside the CIDR range.
    pub contained: bool,
    /// Network address of the CIDR.
    pub network_address: String,
    /// Broadcast (IPv4) or last (IPv6) address of the CIDR.
    pub broadcast_address: String,
}

/// Check whether an IPv4 address is contained within a CIDR range.
///
/// # Errors
///
/// Returns an error if `cidr` is not a valid IPv4 CIDR or `address` is not a
/// valid IPv4 address.
pub fn check_ipv4_contains(cidr: &str, address: &str) -> Result<ContainsResult> {
    let subnet = Ipv4Subnet::from_cidr(cidr)?;
    let addr = Ipv4Addr::from_str(address)
        .map_err(|_| NetcidrError::InvalidIpv4Address(address.to_string()))?;

    let addr_u32 = u32::from(addr);
    let network_u32 = u32::from(subnet.network);
    let mask = ipv4_mask(subnet.prefix_length);

    let contained = (addr_u32 & mask) == (network_u32 & mask);

    Ok(ContainsResult {
        cidr: format!("{}/{}", subnet.network, subnet.prefix_length),
        address: address.to_string(),
        contained,
        network_address: subnet.network.to_string(),
        broadcast_address: subnet.broadcast.to_string(),
    })
}

/// Check whether an IPv6 address is contained within a CIDR range.
///
/// # Errors
///
/// Returns an error if `cidr` is not a valid IPv6 CIDR or `address` is not a
/// valid IPv6 address.
pub fn check_ipv6_contains(cidr: &str, address: &str) -> Result<ContainsResult> {
    let subnet = Ipv6Subnet::from_cidr(cidr)?;
    let addr = Ipv6Addr::from_str(address)
        .map_err(|_| NetcidrError::InvalidIpv6Address(address.to_string()))?;

    let addr_u128 = u128::from(addr);
    let network_u128 = u128::from(subnet.network);
    let mask = ipv6_mask(subnet.prefix_length);

    let contained = (addr_u128 & mask) == (network_u128 & mask);

    Ok(ContainsResult {
        cidr: format!("{}/{}", subnet.network, subnet.prefix_length),
        address: address.to_string(),
        contained,
        network_address: subnet.network.to_string(),
        broadcast_address: subnet.last.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_contained() {
        let result = check_ipv4_contains("192.168.1.0/24", "192.168.1.100").unwrap();
        assert!(result.contained);
        assert_eq!(result.network_address, "192.168.1.0");
        assert_eq!(result.broadcast_address, "192.168.1.255");
    }

    #[test]
    fn test_ipv4_not_contained() {
        let result = check_ipv4_contains("192.168.1.0/24", "10.0.0.1").unwrap();
        assert!(!result.contained);
    }

    #[test]
    fn test_ipv4_slash_32() {
        let result = check_ipv4_contains("10.0.0.1/32", "10.0.0.1").unwrap();
        assert!(result.contained);

        let result = check_ipv4_contains("10.0.0.1/32", "10.0.0.2").unwrap();
        assert!(!result.contained);
    }

    #[test]
    fn test_ipv4_slash_0() {
        let result = check_ipv4_contains("0.0.0.0/0", "255.255.255.255").unwrap();
        assert!(result.contained);
    }

    #[test]
    fn test_ipv6_contained() {
        let result = check_ipv6_contains("2001:db8::/32", "2001:db8::1").unwrap();
        assert!(result.contained);
    }

    #[test]
    fn test_ipv6_not_contained() {
        let result = check_ipv6_contains("2001:db8::/32", "2001:db9::1").unwrap();
        assert!(!result.contained);
    }

    #[test]
    fn test_invalid_ipv4_address() {
        let result = check_ipv4_contains("192.168.1.0/24", "not-an-ip");
        assert!(
            matches!(result, Err(NetcidrError::InvalidIpv4Address(ref s)) if s == "not-an-ip"),
            "expected InvalidIpv4Address, got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_ipv6_address() {
        let result = check_ipv6_contains("2001:db8::/32", "not-an-ip");
        assert!(
            matches!(result, Err(NetcidrError::InvalidIpv6Address(ref s)) if s == "not-an-ip"),
            "expected InvalidIpv6Address, got {:?}",
            result
        );
    }
}
