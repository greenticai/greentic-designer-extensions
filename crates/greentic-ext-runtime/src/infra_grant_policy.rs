//! Admission policy for infra network grants: which tenant-supplied hosts a
//! connection document may widen the allow-list to. Pure and resolver-injected
//! so the accept/reject matrix is testable without a network.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use crate::infra_grant::GrantedTarget;

/// Why a connection document yielded no grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefusal {
    Malformed(&'static str),
    NotHttps,
    BadHost(&'static str),
    BadPort,
    NonPublicAddress,
    ResolutionFailed,
}

impl std::fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(w) => write!(f, "connection document is malformed: {w}"),
            Self::NotHttps => f.write_str("scheme is not https"),
            Self::BadHost(w) => write!(f, "host refused: {w}"),
            Self::BadPort => f.write_str("port is not 1-65535"),
            Self::NonPublicAddress => f.write_str("host resolves to a non-public address"),
            Self::ResolutionFailed => f.write_str("host did not resolve"),
        }
    }
}

/// Is `ip` an address a tenant-supplied host may legitimately point at?
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

pub(crate) fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, including the metadata address
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol 192.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18/15
        || o[0] >= 240) // reserved
}

pub(crate) fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // IPv4-in-IPv6 in every spelling: the embedded address is what is dialled.
    if ip.to_ipv4_mapped().is_some() || ip.to_ipv4().is_some() {
        return false;
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // deprecated site-local
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 64:ff9b::/32 (embeds v4)
        || s[0] == 0x2002 // 6to4 (embeds v4)
        || (s[0] == 0x2001 && s[1] == 0) // Teredo
        || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
}

fn refused_name(host: &str) -> Option<&'static str> {
    const SUFFIXES: [&str; 8] = [
        ".localhost",
        ".local",
        ".internal",
        ".localdomain",
        ".lan",
        ".home.arpa",
        ".in-addr.arpa",
        ".ip6.arpa",
    ];
    if host == "localhost" {
        return Some("localhost");
    }
    if SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Some("internal or local name");
    }
    if !host.contains('.') {
        return Some("single-label name");
    }
    None
}

/// What a hostname resolves to; injectable so tests need no network.
pub trait HostResolver: Send + Sync {
    /// # Errors
    /// Any resolution failure; callers treat it as a refusal.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The operating system resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}

pub(crate) fn all_public(
    resolver: &dyn HostResolver,
    host: &str,
    port: u16,
) -> Result<(), GrantRefusal> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_public_ip(ip) {
            Ok(())
        } else {
            Err(GrantRefusal::NonPublicAddress)
        };
    }
    let ips = resolver
        .resolve(host, port)
        .map_err(|_| GrantRefusal::ResolutionFailed)?;
    if ips.is_empty() {
        return Err(GrantRefusal::ResolutionFailed);
    }
    if ips.into_iter().all(is_public_ip) {
        Ok(())
    } else {
        Err(GrantRefusal::NonPublicAddress)
    }
}

/// Validate the host string alone (no resolution).
fn normalize_host(raw: &str) -> Result<String, GrantRefusal> {
    let host = raw.trim();
    if host.is_empty() {
        return Err(GrantRefusal::BadHost("empty"));
    }
    if host.contains('*') {
        return Err(GrantRefusal::BadHost("wildcard"));
    }
    if host.contains(['@', '/', '\\', '?', '#', '%', ' ', '\t', '\n']) {
        return Err(GrantRefusal::BadHost("not a bare host"));
    }
    if host.contains("://") || !host.is_ascii() {
        return Err(GrantRefusal::BadHost("not a bare ASCII host"));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.contains(':') {
        let ip: Ipv6Addr = bare
            .parse()
            .map_err(|_| GrantRefusal::BadHost("invalid IPv6 literal"))?;
        return if is_public_v6(ip) {
            Ok(ip.to_string())
        } else {
            Err(GrantRefusal::NonPublicAddress)
        };
    }
    // `url` folds the legacy IPv4 spellings (`2130706433`, `0x7f.1`, `127.1`)
    // into the address they denote; classify that, not the spelling.
    match url::Host::parse(bare) {
        Ok(url::Host::Ipv4(ip)) => {
            if is_public_v4(ip) {
                Ok(ip.to_string())
            } else {
                Err(GrantRefusal::NonPublicAddress)
            }
        }
        Ok(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if let Some(why) = refused_name(&d) {
                return Err(GrantRefusal::BadHost(why));
            }
            if d.starts_with(['.', '-']) || d.split('.').any(str::is_empty) {
                return Err(GrantRefusal::BadHost("invalid name"));
            }
            Ok(d)
        }
        Ok(url::Host::Ipv6(_)) | Err(_) => Err(GrantRefusal::BadHost("invalid host")),
    }
}

/// Decide whether a connection document may widen the network allow-list.
///
/// # Errors
/// A [`GrantRefusal`] naming the first rule the document broke.
pub fn admit(doc: &str, resolver: &dyn HostResolver) -> Result<GrantedTarget, GrantRefusal> {
    let v: serde_json::Value =
        serde_json::from_str(doc).map_err(|_| GrantRefusal::Malformed("not json"))?;
    let scheme = v
        .get("scheme")
        .and_then(serde_json::Value::as_str)
        .ok_or(GrantRefusal::Malformed("no scheme"))?;
    if !scheme.trim().eq_ignore_ascii_case("https") {
        return Err(GrantRefusal::NotHttps);
    }
    let host = v
        .get("host")
        .and_then(serde_json::Value::as_str)
        .ok_or(GrantRefusal::Malformed("no host"))?;
    let port = match v.get("port") {
        None | Some(serde_json::Value::Null) => 443,
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(GrantRefusal::BadPort)?,
        Some(serde_json::Value::String(s)) => s.parse().map_err(|_| GrantRefusal::BadPort)?,
        Some(_) => return Err(GrantRefusal::BadPort),
    };
    if port == 0 {
        return Err(GrantRefusal::BadPort);
    }
    let host = normalize_host(host)?;
    all_public(resolver, &host, port)?;
    Ok(GrantedTarget { host, port })
}
