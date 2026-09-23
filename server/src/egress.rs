//! Requests to addresses a named tenant's operator chose: notification
//! destinations and the delivery webhook. They may reach public addresses and
//! the networks `VOTPORT_TENANT_PRIVATE_NETWORKS` names, never the host's
//! loopback, LAN or cloud metadata service. The platform tenant is unrestricted.

use crate::config::IpCidr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Whether a named tenant's request may reach `ip`.
pub fn reachable(ip: IpAddr, allowed: &[IpCidr]) -> bool {
    public(ip) || allowed.iter().any(|block| block.contains(&ip))
}

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // IPv4-compatible and -mapped, NAT64 and 6to4 addresses carry a
            // v4 address that the path may deliver to.
            if let Some(v4) = v6.to_ipv4() {
                return public(v4.into());
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return public(Ipv4Addr::from(u128::from(v6) as u32).into());
            }
            if s[0] == 0x2002 {
                return public(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])).into());
            }
            !(v6.is_multicast()
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// Whether a named tenant's `url` names an address literal it may not reach.
/// Host names are checked when they resolve, by [`restrict`].
pub fn refused_literal(url: &str, allowed: &[IpCidr]) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|url| {
            url.host_str()?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .ok()
        })
        .is_some_and(|ip| !reachable(ip, allowed))
}

/// Resolves only to addresses a named tenant may reach, so a host name that
/// resolves (or rebinds) to an internal address is refused at connect time.
struct TenantResolver(Arc<Vec<IpCidr>>);

impl reqwest::dns::Resolve for TenantResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allowed = Arc::clone(&self.0);
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|address| reachable(address.ip(), &allowed))
                .collect();
            if addresses.is_empty() {
                return Err("the host resolves only to internal addresses".into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Limits a client to addresses a named tenant may reach. Pair it with
/// [`refused_literal`], since address literals skip name resolution.
/// Proxies are not used: a proxy would resolve the destination itself.
pub fn restrict(builder: reqwest::ClientBuilder, allowed: &[IpCidr]) -> reqwest::ClientBuilder {
    builder
        .no_proxy()
        .dns_resolver(Arc::new(TenantResolver(Arc::new(allowed.to_vec()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_and_named_networks_are_reachable() {
        for internal in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.8",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:a00:1::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(!reachable(internal.parse().unwrap(), &[]), "{internal}");
        }
        for external in [
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "64:ff9b::101:101",
            "::ffff:8.8.8.8",
        ] {
            assert!(reachable(external.parse().unwrap(), &[]), "{external}");
        }
        let allowed = [IpCidr::parse("10.1.0.0/16").unwrap()];
        assert!(reachable("10.1.2.3".parse().unwrap(), &allowed));
        assert!(!reachable("10.2.0.1".parse().unwrap(), &allowed));
    }

    #[test]
    fn address_literals_are_checked_and_names_are_left_to_resolution() {
        for refused in [
            "http://127.0.0.1:8080/hook",
            "http://[::1]/hook",
            "http://2130706433/hook",
            "http://0x7f.1/hook",
            "https://169.254.169.254/latest",
        ] {
            assert!(refused_literal(refused, &[]), "{refused}");
        }
        for passed in [
            "https://hooks.slack.com/x",
            "http://localhost/x",
            "https://1.1.1.1/x",
            "",
        ] {
            assert!(!refused_literal(passed, &[]), "{passed}");
        }
    }

    #[tokio::test]
    async fn a_restricted_client_refuses_a_name_that_resolves_internally() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = restrict(reqwest::Client::builder().no_proxy(), &[])
            .build()
            .unwrap();
        let refused = client.get(format!("http://localhost:{port}/")).send().await;
        assert!(refused.is_err());
        let allowed = [IpCidr::parse("127.0.0.0/8").unwrap()];
        let client = restrict(reqwest::Client::builder().no_proxy(), &allowed)
            .build()
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let reached = client.get(format!("http://localhost:{port}/")).send().await;
        server.abort();
        assert_eq!(reached.unwrap().status(), 204);
    }
}
