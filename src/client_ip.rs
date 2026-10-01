//! Which address identifies a client for per-IP rate limiting.
//!
//! A forwarding header is only as trustworthy as the proxy that set it.
//! Proxies such as CloudFront *append* the address they saw to a
//! client-supplied `X-Forwarded-For`, so its leftmost entry is whatever the
//! client chose. [`ClientIpSource`] therefore names the one place a trusted
//! proxy (or the TCP connection) puts the real address, and nothing else is
//! believed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::{HeaderName, Request};
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

use crate::error::NetcidrError;

/// Most proxies a deployment can sensibly sit behind.
const MAX_TRUSTED_HOPS: u8 = 10;

/// Where the client's address comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIpSource {
    /// The TCP peer. Right for `netcidr serve` with clients connecting
    /// directly.
    Peer,
    /// The `hops`-th entry from the right of `X-Forwarded-For`: with `hops`
    /// trusted proxies in front, that is the address the outermost one
    /// saw. Entries further left are client-controlled.
    ForwardedFor { hops: u8 },
    /// A header a trusted proxy sets to the client address (`IP` or
    /// `IP:port`), e.g. CloudFront's `cloudfront-viewer-address`.
    Header(HeaderName),
}

impl FromStr for ClientIpSource {
    type Err = NetcidrError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            NetcidrError::InvalidInput(
                "client_ip_source must be 'peer', 'xff:<1-10>', or 'header:<name>'".to_string(),
            )
        };
        let raw = raw.trim();
        if raw == "peer" {
            return Ok(Self::Peer);
        }
        if let Some(hops) = raw.strip_prefix("xff:") {
            return match hops.parse::<u8>() {
                Ok(hops) if (1..=MAX_TRUSTED_HOPS).contains(&hops) => {
                    Ok(Self::ForwardedFor { hops })
                }
                _ => Err(invalid()),
            };
        }
        if let Some(name) = raw.strip_prefix("header:") {
            return HeaderName::from_str(&name.to_ascii_lowercase())
                .map(Self::Header)
                .map_err(|_| invalid());
        }
        Err(invalid())
    }
}

impl TryFrom<String> for ClientIpSource {
    type Error = NetcidrError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

impl<'de> serde::Deserialize<'de> for ClientIpSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl ClientIpSource {
    /// The client address for `req`, or `None` if this source has none.
    pub fn client_ip<T>(&self, req: &Request<T>) -> Option<IpAddr> {
        match self {
            Self::Peer => req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
            Self::ForwardedFor { hops } => {
                // Several X-Forwarded-For headers are one comma list, in order.
                let entries: Vec<&str> = req
                    .headers()
                    .get_all("x-forwarded-for")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(','))
                    .map(str::trim)
                    .collect();
                // No skipping over junk: a client could otherwise append
                // garbage to shift which entry is trusted.
                entries
                    .len()
                    .checked_sub(usize::from(*hops))
                    .and_then(|i| entries[i].parse().ok())
            }
            Self::Header(name) => req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_ip_maybe_port),
        }
    }
}

/// `IP`, `IPv4:port`, `[IPv6]:port`, or CloudFront's unbracketed
/// `IPv6:port`.
fn parse_ip_maybe_port(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse() {
        return Some(ip);
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    let (ip, port) = raw.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    ip.parse().ok()
}

/// The rate-limit key for a client address. IPv6 clients are keyed by
/// their /64: one subscriber usually holds a whole /64, so per-address
/// limits would let them rotate addresses freely. It also absorbs the
/// ambiguity of CloudFront's unbracketed `IPv6:port`, whose port lands in
/// the low 64 bits however it is read. IPv4-mapped IPv6 is keyed as IPv4.
pub fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
    }
}

/// Rate-limit key extractor for a [`ClientIpSource`]; see
/// [`rate_limit_key`]. A request with no usable address is keyed to
/// `0.0.0.0`: such requests share one bucket rather than failing, and
/// rather than each picking their own.
#[derive(Debug, Clone)]
pub struct ClientIpKeyExtractor(Arc<ClientIpSource>);

impl ClientIpKeyExtractor {
    pub fn new(source: ClientIpSource) -> Self {
        Self(Arc::new(source))
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        Ok(self
            .0
            .client_ip(req)
            .map(rate_limit_key)
            .unwrap_or_else(|| {
                tracing::debug!(source = ?self.0, "no client address; using shared rate-limit bucket");
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder();
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(()).unwrap()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn parses_the_three_sources_and_rejects_the_rest() {
        assert_eq!(
            "peer".parse::<ClientIpSource>().unwrap(),
            ClientIpSource::Peer
        );
        assert_eq!(
            "xff:2".parse::<ClientIpSource>().unwrap(),
            ClientIpSource::ForwardedFor { hops: 2 }
        );
        assert_eq!(
            "header:CloudFront-Viewer-Address"
                .parse::<ClientIpSource>()
                .unwrap(),
            ClientIpSource::Header(HeaderName::from_static("cloudfront-viewer-address"))
        );
        for bad in [
            "",
            "xff",
            "xff:0",
            "xff:11",
            "xff:-1",
            "header:",
            "header:bad name",
            "smart",
        ] {
            assert!(bad.parse::<ClientIpSource>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn forwarded_for_trusts_only_the_proxy_appended_entries() {
        let one_hop = ClientIpSource::ForwardedFor { hops: 1 };
        // A client-supplied entry on the left is ignored.
        let spoofed = req(&[("x-forwarded-for", "6.6.6.6, 203.0.113.7")]);
        assert_eq!(one_hop.client_ip(&spoofed), ip("203.0.113.7"));
        // Repeated headers form one list.
        let split = req(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        assert_eq!(one_hop.client_ip(&split), ip("203.0.113.7"));

        let two_hops = ClientIpSource::ForwardedFor { hops: 2 };
        let chain = req(&[("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.0.0.1")]);
        assert_eq!(two_hops.client_ip(&chain), ip("203.0.113.7"));
        // Too few entries, or junk where the trusted entry should be: none.
        assert_eq!(
            two_hops.client_ip(&req(&[("x-forwarded-for", "203.0.113.7")])),
            None
        );
        assert_eq!(
            one_hop.client_ip(&req(&[("x-forwarded-for", "203.0.113.7, junk")])),
            None
        );
        assert_eq!(one_hop.client_ip(&req(&[])), None);
    }

    #[test]
    fn header_source_reads_ip_with_or_without_port() {
        let source = ClientIpSource::Header(HeaderName::from_static("cloudfront-viewer-address"));
        for (value, want) in [
            ("198.51.100.10:46532", "198.51.100.10"),
            ("198.51.100.10", "198.51.100.10"),
            ("2001:db8::1:46532", "2001:db8::1"),
            ("[2001:db8::1]:46532", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            let r = req(&[("cloudfront-viewer-address", value)]);
            assert_eq!(source.client_ip(&r), ip(want), "{value}");
        }
        assert_eq!(
            source.client_ip(&req(&[("cloudfront-viewer-address", "nope")])),
            None
        );
        // Other headers are not consulted.
        assert_eq!(
            source.client_ip(&req(&[("x-forwarded-for", "203.0.113.7")])),
            None
        );
    }

    #[test]
    fn peer_source_uses_the_connection_and_ignores_headers() {
        let mut r = req(&[("x-forwarded-for", "6.6.6.6")]);
        assert_eq!(ClientIpSource::Peer.client_ip(&r), None);
        r.extensions_mut()
            .insert(ConnectInfo("192.0.2.5:5000".parse::<SocketAddr>().unwrap()));
        assert_eq!(ClientIpSource::Peer.client_ip(&r), ip("192.0.2.5"));
    }

    #[test]
    fn ipv6_clients_share_a_key_per_slash_64() {
        let key = |s: &str| rate_limit_key(s.parse().unwrap());
        assert_eq!(key("203.0.113.7"), key("203.0.113.7"));
        assert_ne!(key("203.0.113.7"), key("203.0.113.8"));
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:203.0.113.7"), key("203.0.113.7"));

        // CloudFront's `IPv6:port` read either way lands in the same /64,
        // so a client cannot pick its bucket by choosing a source port.
        let source = ClientIpSource::Header(HeaderName::from_static("cloudfront-viewer-address"));
        let extractor = ClientIpKeyExtractor::new(source);
        let keys: Vec<IpAddr> = ["2001:db8::1:8080", "2001:db8::1:443", "2001:db8::1:46532"]
            .iter()
            .map(|v| {
                extractor
                    .extract(&req(&[("cloudfront-viewer-address", v)]))
                    .unwrap()
            })
            .collect();
        assert!(keys.iter().all(|k| *k == key("2001:db8::")), "{keys:?}");
    }

    #[test]
    fn a_missing_address_shares_one_bucket() {
        let extractor = ClientIpKeyExtractor::new(ClientIpSource::ForwardedFor { hops: 1 });
        assert_eq!(
            extractor.extract(&req(&[])).unwrap(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }
}
