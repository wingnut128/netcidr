use std::net::IpAddr;

/// Decompose an IP address into its PTR record label and reverse zone name.
///
/// For IPv4 `192.168.1.10` → `("10", "1.168.192.in-addr.arpa")`
/// For IPv6, nibble-expands and reverses under `ip6.arpa`.
pub fn ptr_components(ip: IpAddr) -> (String, String) {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let label = octets[3].to_string();
            let zone = format!("{}.{}.{}.in-addr.arpa", octets[2], octets[1], octets[0]);
            (label, zone)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut nibbles = Vec::with_capacity(32);
            for seg in &segments {
                nibbles.push(format!("{:04x}", seg));
            }
            let all_nibbles: Vec<char> = nibbles.iter().flat_map(|s| s.chars()).collect();
            // Reverse nibbles: label is the last nibble, zone is the rest
            let reversed: Vec<String> = all_nibbles.iter().rev().map(|c| c.to_string()).collect();
            // Split: first nibble char is the host part (label), rest form the zone
            let label = reversed[0].clone();
            let zone_nibbles = &reversed[1..];
            let zone = format!("{}.ip6.arpa", zone_nibbles.join("."));
            (label, zone)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ptr_components_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let (label, zone) = ptr_components(ip);
        assert_eq!(label, "10");
        assert_eq!(zone, "1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ptr_components_v6() {
        // 2001:db8::1 expands to 2001:0db8:0000:0000:0000:0000:0000:0001
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let (label, zone) = ptr_components(ip);
        assert_eq!(label, "1");
        // The zone is the reversed nibbles (minus the last) joined by dots + .ip6.arpa
        assert!(zone.ends_with(".ip6.arpa"));
        assert_eq!(
            zone.len(),
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa".len()
        );
    }
}
