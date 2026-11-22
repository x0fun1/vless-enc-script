// SPDX-License-Identifier: MPL-2.0
// Special-use ranges follow Xray-core v26.11.9 common/geodata/consts.go.
use std::{net::IpAddr, sync::OnceLock};

const RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/29",
    "192.0.0.8/32",
    "192.0.0.9/32",
    "192.0.0.10/32",
    "192.0.0.170/32",
    "192.0.0.171/32",
    "192.0.2.0/24",
    "192.52.193.0/24",
    "192.88.99.2/32",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "224.0.0.0/4",
    "::1/128",
    "::/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/32",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:1::3/128",
    "2001:2::/48",
    "2001:3::/32",
    "2001:20::/28",
    "2001:30::/28",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub fn private_ip(ip: IpAddr) -> bool {
    type Range = (bool, u128, u128);
    static PARSED: OnceLock<Vec<Range>> = OnceLock::new();
    let ip = match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        a => a,
    };
    let (v4, address) = match ip {
        IpAddr::V4(ip) => (true, u32::from(ip) as u128),
        IpAddr::V6(ip) => (false, u128::from(ip)),
    };
    PARSED
        .get_or_init(|| {
            RANGES
                .iter()
                .map(|range| {
                    let (address, prefix) = range.split_once('/').expect("static CIDR");
                    let address: IpAddr = address.parse().expect("static CIDR address");
                    let prefix: u32 = prefix.parse().expect("static CIDR prefix");
                    match address {
                        IpAddr::V4(ip) => (
                            true,
                            u32::from(ip) as u128,
                            (u32::MAX << (32 - prefix)) as u128,
                        ),
                        IpAddr::V6(ip) => (false, u128::from(ip), u128::MAX << (128 - prefix)),
                    }
                })
                .collect()
        })
        .iter()
        .any(|(family, network, mask)| *family == v4 && address & mask == network & mask)
}

pub fn private_domain(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !host.contains('.') {
        return true;
    }
    [
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
    ]
    .iter()
    .any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_ipv4_mapped_and_ipv6_special_ranges() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "::ffff:192.168.1.1",
            "::1",
            "fc00::1",
            "64:ff9b::7f00:1",
            "2001:db8::1",
        ] {
            assert!(private_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(!private_ip(address.parse().unwrap()));
        }
        assert!(private_domain("a.localhost."));
        assert!(private_domain("localhost"));
        assert!(!private_domain("www.nvidia.com"));
    }
}
