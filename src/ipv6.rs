use crate::error::{IpCalcError, Result};
use crate::validation;
use serde::Serialize;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv6Subnet {
    pub input: String,
    #[serde(rename = "network_address")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub network: Ipv6Addr,
    pub network_address_full: String,
    #[serde(rename = "last_address")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub last: Ipv6Addr,
    pub last_address_full: String,
    pub prefix_length: u8,
    pub total_addresses: String,
    pub hextets: Vec<String>,
    pub address_type: String,
}

/// Compute the IPv6 subnet mask for a given prefix length.
/// Prefix must be 0..=128; values outside this range produce meaningless results.
pub fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    }
}

impl Ipv6Subnet {
    pub fn from_cidr(cidr: &str) -> Result<Self> {
        validation::validate_cidr(cidr)?;

        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| IpCalcError::InvalidCidr(cidr.to_string()))?;

        let addr = Ipv6Addr::from_str(addr_str)
            .map_err(|_| IpCalcError::InvalidIpv6Address(addr_str.to_string()))?;

        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| IpCalcError::InvalidCidr(cidr.to_string()))?;

        Self::new(addr, prefix)
    }

    pub fn new(addr: Ipv6Addr, prefix: u8) -> Result<Self> {
        if prefix > 128 {
            return Err(IpCalcError::InvalidPrefixLength(prefix));
        }

        let addr_u128 = u128::from(addr);
        let mask = ipv6_mask(prefix);

        let network = addr_u128 & mask;
        let last = network | !mask;

        let network_addr = Ipv6Addr::from(network);
        let last_addr = Ipv6Addr::from(last);

        let segments = network_addr.segments();
        let hextets: Vec<String> = segments.iter().map(|s| format!("{:04x}", s)).collect();

        let total_addresses = if prefix == 128 {
            "1".to_string()
        } else {
            let bits = 128 - prefix;
            if bits <= 64 {
                format!("{}", 2u128.pow(bits as u32))
            } else {
                format!("2^{}", bits)
            }
        };

        let address_type = Self::determine_address_type(&network_addr);

        Ok(Self {
            input: format!("{}/{}", addr, prefix),
            network: network_addr,
            network_address_full: hextets.join(":"),
            last: last_addr,
            last_address_full: Self::format_full(&last_addr),
            prefix_length: prefix,
            total_addresses,
            hextets,
            address_type,
        })
    }

    fn format_full(addr: &Ipv6Addr) -> String {
        let s = addr.segments();
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
        )
    }

    fn determine_address_type(addr: &Ipv6Addr) -> String {
        if addr.is_loopback() {
            "Loopback (RFC 4291)".to_string()
        } else if addr.is_unspecified() {
            "Unspecified (RFC 4291)".to_string()
        } else if addr.is_multicast() {
            "Multicast (RFC 4291)".to_string()
        } else if Self::is_link_local(addr) {
            "Link-Local Unicast (RFC 4291)".to_string()
        } else if Self::is_unique_local(addr) {
            "Unique Local Address (RFC 4193)".to_string()
        } else if Self::is_documentation(addr) {
            "Documentation (RFC 3849)".to_string()
        } else if Self::is_global_unicast(addr) {
            "Global Unicast (RFC 4291)".to_string()
        } else {
            "Other".to_string()
        }
    }

    fn is_documentation(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        segments[0] == 0x2001 && segments[1] == 0x0db8
    }

    fn is_link_local(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        (segments[0] & 0xffc0) == 0xfe80
    }

    fn is_unique_local(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        (segments[0] & 0xfe00) == 0xfc00
    }

    fn is_global_unicast(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        (segments[0] & 0xe000) == 0x2000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_subnet_64() {
        let subnet = Ipv6Subnet::from_cidr("2001:db8:85a3::8a2e:370:7334/64").unwrap();
        assert_eq!(
            subnet.network,
            Ipv6Addr::from_str("2001:db8:85a3::").unwrap()
        );
        assert_eq!(
            subnet.network_address_full,
            "2001:0db8:85a3:0000:0000:0000:0000:0000"
        );
        assert_eq!(subnet.prefix_length, 64);
        assert_eq!(subnet.address_type, "Documentation (RFC 3849)");
    }

    #[test]
    fn test_ipv6_subnet_128() {
        let subnet = Ipv6Subnet::from_cidr("::1/128").unwrap();
        assert_eq!(subnet.network, Ipv6Addr::from_str("::1").unwrap());
        assert_eq!(subnet.total_addresses, "1");
        assert_eq!(subnet.address_type, "Loopback (RFC 4291)");
    }

    #[test]
    fn test_ipv6_link_local() {
        let subnet = Ipv6Subnet::from_cidr("fe80::1/10").unwrap();
        assert_eq!(subnet.address_type, "Link-Local Unicast (RFC 4291)");
    }

    #[test]
    fn test_ipv6_ula() {
        let subnet = Ipv6Subnet::from_cidr("fd00::1/8").unwrap();
        assert_eq!(subnet.address_type, "Unique Local Address (RFC 4193)");
    }

    #[test]
    fn test_ipv6_documentation() {
        let subnet = Ipv6Subnet::from_cidr("2001:db8::/32").unwrap();
        assert_eq!(subnet.address_type, "Documentation (RFC 3849)");
    }

    #[test]
    fn test_ipv6_global_unicast() {
        let subnet = Ipv6Subnet::from_cidr("2001:4860::/32").unwrap();
        assert_eq!(subnet.address_type, "Global Unicast (RFC 4291)");
    }

    #[test]
    fn test_invalid_prefix() {
        let result = Ipv6Subnet::from_cidr("2001:db8::/129");
        assert!(
            matches!(result, Err(IpCalcError::InvalidPrefixLength(129))),
            "expected InvalidPrefixLength(129), got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_cidr_no_slash() {
        let result = Ipv6Subnet::from_cidr("2001:db8::");
        assert!(
            matches!(result, Err(IpCalcError::InvalidCidr(_))),
            "expected InvalidCidr, got {:?}",
            result
        );
    }

    #[test]
    fn test_input_too_long() {
        let long_input = "a".repeat(300);
        let result = Ipv6Subnet::from_cidr(&long_input);
        assert!(
            matches!(
                result,
                Err(IpCalcError::InputTooLong {
                    length: 300,
                    limit: 256
                })
            ),
            "expected InputTooLong, got {:?}",
            result
        );
    }

    #[test]
    fn test_ipv6_entire_space_prefix_0() {
        let subnet = Ipv6Subnet::from_cidr("::/0").unwrap();
        assert_eq!(subnet.network, Ipv6Addr::from_str("::").unwrap());
        assert_eq!(
            subnet.last,
            Ipv6Addr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        );
        assert_eq!(subnet.prefix_length, 0);
        assert_eq!(subnet.total_addresses, "2^128");
        assert_eq!(
            subnet.network_address_full,
            "0000:0000:0000:0000:0000:0000:0000:0000"
        );
        assert_eq!(
            subnet.last_address_full,
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        );
        // ipv6_mask(0) should be all zeros
        assert_eq!(ipv6_mask(0), 0u128);
    }

    #[test]
    fn test_ipv6_loopback_single_host() {
        let subnet = Ipv6Subnet::from_cidr("::1/128").unwrap();
        assert_eq!(subnet.network, Ipv6Addr::from_str("::1").unwrap());
        assert_eq!(subnet.last, Ipv6Addr::from_str("::1").unwrap());
        assert_eq!(subnet.total_addresses, "1");
        assert_eq!(subnet.prefix_length, 128);
        assert_eq!(subnet.address_type, "Loopback (RFC 4291)");
    }

    #[test]
    fn test_ipv6_multicast_prefix_8() {
        let subnet = Ipv6Subnet::from_cidr("ff02::1/8").unwrap();
        // Network should be masked to ff00::
        assert_eq!(subnet.network, Ipv6Addr::from_str("ff00::").unwrap());
        assert_eq!(subnet.prefix_length, 8);
        assert_eq!(subnet.address_type, "Multicast (RFC 4291)");
        assert_eq!(
            subnet.last,
            Ipv6Addr::from_str("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        );
    }

    #[test]
    fn test_ipv6_unspecified_single_host() {
        let subnet = Ipv6Subnet::from_cidr("::/128").unwrap();
        assert_eq!(subnet.network, Ipv6Addr::from_str("::").unwrap());
        assert_eq!(subnet.last, Ipv6Addr::from_str("::").unwrap());
        assert_eq!(subnet.total_addresses, "1");
        assert_eq!(subnet.prefix_length, 128);
        assert_eq!(subnet.address_type, "Unspecified (RFC 4291)");
    }

    #[test]
    fn test_ipv6_non_normalized_input() {
        // 2001:db8::1/32 should normalize the network address to 2001:db8::
        let subnet = Ipv6Subnet::from_cidr("2001:db8::1/32").unwrap();
        assert_eq!(subnet.network, Ipv6Addr::from_str("2001:db8::").unwrap());
        assert_eq!(
            subnet.network_address_full,
            "2001:0db8:0000:0000:0000:0000:0000:0000"
        );
        assert_eq!(subnet.prefix_length, 32);
        assert_eq!(subnet.address_type, "Documentation (RFC 3849)");
        // The input field should record the original address (parsed, not raw)
        assert_eq!(subnet.input, "2001:db8::1/32");
    }

    #[test]
    fn test_json_serialization_field_names() {
        let subnet = Ipv6Subnet::from_cidr("2001:db8::/32").unwrap();
        let json: serde_json::Value = serde_json::to_value(&subnet).unwrap();
        // Verify serde(rename) produces the expected JSON keys
        assert_eq!(json["network_address"], "2001:db8::");
        assert!(json["network_address_full"].is_string());
        assert!(json["last_address"].is_string());
        assert!(json["last_address_full"].is_string());
        assert_eq!(json["prefix_length"], 32);
    }
}
