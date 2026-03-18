use crate::error::{IpCalcError, Result};
use crate::validation;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Calculated properties of an IPv4 subnet.
///
/// Contains the network address, broadcast address, subnet mask, host range,
/// and metadata such as network class, privacy status, and address type
/// (e.g., RFC 1918, multicast).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct Ipv4Subnet {
    /// The original CIDR input string (normalized to `address/prefix`).
    pub input: String,
    /// Network (base) address of the subnet.
    #[serde(rename = "network_address")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub network: Ipv4Addr,
    /// Broadcast address of the subnet.
    #[serde(rename = "broadcast_address")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub broadcast: Ipv4Addr,
    /// Subnet mask (e.g., `255.255.255.0` for a `/24`).
    #[serde(rename = "subnet_mask")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub mask: Ipv4Addr,
    /// Wildcard (inverse) mask.
    #[serde(rename = "wildcard_mask")]
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub wildcard: Ipv4Addr,
    /// CIDR prefix length (0--32).
    pub prefix_length: u8,
    /// First usable host address (equals `network` for /31 and /32).
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub first_host: Ipv4Addr,
    /// Last usable host address (equals `broadcast` for /31 and /32).
    #[cfg_attr(feature = "swagger", schema(value_type = String))]
    pub last_host: Ipv4Addr,
    /// Total number of addresses in the subnet (including network and broadcast).
    pub total_hosts: u64,
    /// Number of usable host addresses (excludes network and broadcast for prefixes < /31).
    pub usable_hosts: u64,
    /// Legacy classful network class (A, B, C, D, or E).
    pub network_class: String,
    /// Whether the address falls in a private, loopback, link-local, or CGN range.
    pub is_private: bool,
    /// Human-readable address-type label with RFC reference (e.g., "Private (RFC 1918)").
    pub address_type: String,
}

/// Compute the IPv4 subnet mask for a given prefix length.
/// Prefix must be 0..=32; values outside this range produce meaningless results.
pub fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

impl Ipv4Subnet {
    /// Parse an IPv4 CIDR string (e.g., `"192.168.1.0/24"`) and compute subnet properties.
    ///
    /// # Errors
    ///
    /// Returns an error if the input fails validation, contains an invalid IPv4
    /// address, or has a prefix length outside 0--32.
    pub fn from_cidr(cidr: &str) -> Result<Self> {
        validation::validate_cidr(cidr)?;

        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| IpCalcError::InvalidCidr(cidr.to_string()))?;

        let addr = Ipv4Addr::from_str(addr_str)
            .map_err(|_| IpCalcError::InvalidIpv4Address(addr_str.to_string()))?;

        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| IpCalcError::InvalidCidr(cidr.to_string()))?;

        Self::new(addr, prefix)
    }

    /// Build an [`Ipv4Subnet`] from a parsed address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`IpCalcError::InvalidPrefixLength`] if `prefix` exceeds 32.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self> {
        if prefix > 32 {
            return Err(IpCalcError::InvalidPrefixLength(prefix));
        }

        let addr_u32 = u32::from(addr);
        let mask = ipv4_mask(prefix);
        let wildcard_val = !mask;

        let network = addr_u32 & mask;
        let broadcast = network | wildcard_val;

        let network_addr = Ipv4Addr::from(network);
        let broadcast_addr = Ipv4Addr::from(broadcast);
        let subnet_mask = Ipv4Addr::from(mask);
        let wildcard_mask = Ipv4Addr::from(wildcard_val);

        let total_hosts = if prefix == 32 {
            1
        } else {
            2u64.pow((32 - prefix) as u32)
        };
        let usable_hosts = if prefix >= 31 {
            total_hosts
        } else {
            total_hosts.saturating_sub(2)
        };

        let (first_host, last_host) = if prefix >= 31 {
            (network_addr, broadcast_addr)
        } else {
            (Ipv4Addr::from(network + 1), Ipv4Addr::from(broadcast - 1))
        };

        let first_octet = addr.octets()[0];
        let network_class = match first_octet {
            0..=127 => "A",
            128..=191 => "B",
            192..=223 => "C",
            224..=239 => "D (Multicast)",
            240..=255 => "E (Reserved)",
        }
        .to_string();

        let is_private = addr.is_private()
            || (addr.octets()[0] == 100 && (addr.octets()[1] & 0xC0) == 64) // 100.64.0.0/10
            || addr.is_loopback()
            || addr.is_link_local();

        let address_type = Self::determine_address_type(network);

        Ok(Self {
            input: format!("{}/{}", addr, prefix),
            network: network_addr,
            broadcast: broadcast_addr,
            mask: subnet_mask,
            wildcard: wildcard_mask,
            prefix_length: prefix,
            first_host,
            last_host,
            total_hosts,
            usable_hosts,
            network_class,
            is_private,
            address_type,
        })
    }

    fn determine_address_type(network: u32) -> String {
        // Check more-specific ranges before less-specific ones
        let label = if network & 0xff00_0000 == 0x0000_0000 {
            // 0.0.0.0/8
            "Current Network (RFC 1122)"
        } else if network & 0xff00_0000 == 0x0a00_0000 {
            // 10.0.0.0/8
            "Private (RFC 1918)"
        } else if network & 0xffc0_0000 == 0x6440_0000 {
            // 100.64.0.0/10
            "Carrier-Grade NAT (RFC 6598)"
        } else if network & 0xff00_0000 == 0x7f00_0000 {
            // 127.0.0.0/8
            "Loopback (RFC 1122)"
        } else if network & 0xffff_0000 == 0xa9fe_0000 {
            // 169.254.0.0/16
            "Link-Local (RFC 3927)"
        } else if network & 0xfff0_0000 == 0xac10_0000 {
            // 172.16.0.0/12
            "Private (RFC 1918)"
        } else if network & 0xffff_ff00 == 0xc000_0200 {
            // 192.0.2.0/24 — check before 192.0.0.0/24
            "Documentation TEST-NET-1 (RFC 5737)"
        } else if network & 0xffff_ff00 == 0xc000_0000 {
            // 192.0.0.0/24
            "IETF Protocol Assignments (RFC 6890)"
        } else if network & 0xffff_ff00 == 0xc058_6300 {
            // 192.88.99.0/24
            "6to4 Relay Anycast (RFC 7526)"
        } else if network & 0xffff_0000 == 0xc0a8_0000 {
            // 192.168.0.0/16
            "Private (RFC 1918)"
        } else if network & 0xfffe_0000 == 0xc612_0000 {
            // 198.18.0.0/15
            "Benchmarking (RFC 2544)"
        } else if network & 0xffff_ff00 == 0xc633_6400 {
            // 198.51.100.0/24
            "Documentation TEST-NET-2 (RFC 5737)"
        } else if network & 0xffff_ff00 == 0xcb00_7100 {
            // 203.0.113.0/24
            "Documentation TEST-NET-3 (RFC 5737)"
        } else if network & 0xf000_0000 == 0xe000_0000 {
            // 224.0.0.0/4
            "Multicast (RFC 5771)"
        } else if network & 0xf000_0000 == 0xf000_0000 {
            // 240.0.0.0/4
            "Reserved (RFC 1112)"
        } else {
            "Public"
        };
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_subnet_24() {
        let subnet = Ipv4Subnet::from_cidr("192.168.1.100/24").unwrap();
        assert_eq!(subnet.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnet.broadcast, Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(subnet.mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet.wildcard, Ipv4Addr::new(0, 0, 0, 255));
        assert_eq!(subnet.first_host, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(subnet.last_host, Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(subnet.total_hosts, 256);
        assert_eq!(subnet.usable_hosts, 254);
    }

    #[test]
    fn test_ipv4_subnet_32() {
        let subnet = Ipv4Subnet::from_cidr("10.0.0.1/32").unwrap();
        assert_eq!(subnet.network, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(subnet.broadcast, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(subnet.total_hosts, 1);
        assert_eq!(subnet.usable_hosts, 1);
    }

    #[test]
    fn test_ipv4_subnet_31() {
        let subnet = Ipv4Subnet::from_cidr("10.0.0.0/31").unwrap();
        assert_eq!(subnet.network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(subnet.broadcast, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(subnet.total_hosts, 2);
        assert_eq!(subnet.usable_hosts, 2);
    }

    #[test]
    fn test_private_address() {
        let subnet = Ipv4Subnet::from_cidr("192.168.1.0/24").unwrap();
        assert!(subnet.is_private);

        let subnet = Ipv4Subnet::from_cidr("8.8.8.0/24").unwrap();
        assert!(!subnet.is_private);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = Ipv4Subnet::from_cidr("192.168.1.0/33");
        assert!(
            matches!(result, Err(IpCalcError::InvalidPrefixLength(33))),
            "expected InvalidPrefixLength(33), got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_cidr_no_slash() {
        let result = Ipv4Subnet::from_cidr("192.168.1.0");
        assert!(
            matches!(result, Err(IpCalcError::InvalidCidr(_))),
            "expected InvalidCidr, got {:?}",
            result
        );
    }

    #[test]
    fn test_input_too_long() {
        let long_input = "a".repeat(300);
        let result = Ipv4Subnet::from_cidr(&long_input);
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
    fn test_address_type_rfc_ranges() {
        let cases = vec![
            ("0.0.0.0/8", "Current Network (RFC 1122)"),
            ("10.0.0.0/8", "Private (RFC 1918)"),
            ("100.64.0.0/10", "Carrier-Grade NAT (RFC 6598)"),
            ("127.0.0.0/8", "Loopback (RFC 1122)"),
            ("169.254.0.0/16", "Link-Local (RFC 3927)"),
            ("172.16.0.0/12", "Private (RFC 1918)"),
            ("192.0.0.0/24", "IETF Protocol Assignments (RFC 6890)"),
            ("192.0.2.0/24", "Documentation TEST-NET-1 (RFC 5737)"),
            ("192.88.99.0/24", "6to4 Relay Anycast (RFC 7526)"),
            ("192.168.0.0/16", "Private (RFC 1918)"),
            ("198.18.0.0/15", "Benchmarking (RFC 2544)"),
            ("198.51.100.0/24", "Documentation TEST-NET-2 (RFC 5737)"),
            ("203.0.113.0/24", "Documentation TEST-NET-3 (RFC 5737)"),
            ("224.0.0.0/4", "Multicast (RFC 5771)"),
            ("240.0.0.0/4", "Reserved (RFC 1112)"),
            ("8.8.8.0/24", "Public"),
            ("1.1.1.0/24", "Public"),
        ];

        for (cidr, expected) in cases {
            let subnet = Ipv4Subnet::from_cidr(cidr).unwrap();
            assert_eq!(
                subnet.address_type, expected,
                "Failed for {}: got '{}', expected '{}'",
                cidr, subnet.address_type, expected
            );
        }
    }

    #[test]
    fn test_json_serialization_field_names() {
        let subnet = Ipv4Subnet::from_cidr("192.168.1.0/24").unwrap();
        let json: serde_json::Value = serde_json::to_value(&subnet).unwrap();
        // Verify serde(rename) produces the expected JSON keys
        assert_eq!(json["network_address"], "192.168.1.0");
        assert_eq!(json["broadcast_address"], "192.168.1.255");
        assert_eq!(json["subnet_mask"], "255.255.255.0");
        assert_eq!(json["wildcard_mask"], "0.0.0.255");
        assert_eq!(json["first_host"], "192.168.1.1");
        assert_eq!(json["last_host"], "192.168.1.254");
        assert_eq!(json["prefix_length"], 24);
    }
}
