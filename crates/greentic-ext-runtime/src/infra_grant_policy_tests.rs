//! Accept/reject matrix for the infra grant admission policy.

use std::sync::Arc;

use crate::infra_grant::{GrantRefusal, admit, is_public_ip};
use crate::infra_grant_tests::{FakeDns, doc, public_dns};

#[test]
fn a_public_https_host_is_admitted() {
    let t = admit(
        &doc("Qdrant.Acme.Example.", 6333, "https"),
        public_dns().as_ref(),
    );
    // trailing dot stripped, lower-cased; the fake table is keyed lower-case
    assert_eq!(t.unwrap().host, "qdrant.acme.example");
}

#[test]
fn hosts_that_must_be_refused() {
    let dns = Arc::new(FakeDns::default());
    for host in [
        "localhost",
        "foo.localhost",
        "svc.internal",
        "box.local",
        "x.localdomain",
        "router.lan",
        "nas.home.arpa",
        "qdrant",
        "127.0.0.1",
        "2130706433",
        "0x7f.1",
        "127.1",
        "10.0.0.5",
        "172.16.4.4",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.18.0.1",
        "[::1]",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "::8.8.8.8",
        "64:ff9b::808:808",
        "2002:808:808::1",
        "2001:db8::1",
        "user@evil.example",
        "evil.example/path",
        "*.example.com",
        "*",
        "",
        "  ",
        "https://evil.example",
        "evil.example:443",
        "évil.example",
        "a..b.example",
        "-x.example",
        "a b.example",
    ] {
        assert!(
            admit(&doc(host, 443, "https"), dns.as_ref()).is_err(),
            "{host:?} must be refused"
        );
    }
}

#[test]
fn ip_literals_are_judged_without_dns() {
    let dns = Arc::new(FakeDns::default());
    assert!(admit(&doc("8.8.8.8", 443, "https"), dns.as_ref()).is_ok());
    assert!(admit(&doc("2606:4700:4700::1111", 443, "https"), dns.as_ref()).is_ok());
}

#[test]
fn only_https_is_accepted() {
    for scheme in ["http", "ftp", "", "HTTP"] {
        assert_eq!(
            admit(
                &doc("qdrant.acme.example", 443, scheme),
                public_dns().as_ref()
            ),
            Err(GrantRefusal::NotHttps),
            "{scheme:?}"
        );
    }
    assert!(
        admit(
            &doc("qdrant.acme.example", 443, "HTTPS"),
            public_dns().as_ref()
        )
        .is_ok()
    );
    assert!(
        admit(
            r#"{"host":"qdrant.acme.example","port":443}"#,
            public_dns().as_ref()
        )
        .is_err()
    );
}

#[test]
fn ports_are_validated() {
    let dns = public_dns();
    for bad in ["0", "65536", "-1", "\"x\"", "true", "1.5"] {
        let d = format!(r#"{{"host":"qdrant.acme.example","port":{bad},"scheme":"https"}}"#);
        assert!(admit(&d, dns.as_ref()).is_err(), "port {bad}");
    }
    let d = r#"{"host":"qdrant.acme.example","scheme":"https"}"#;
    assert_eq!(
        admit(d, dns.as_ref()).unwrap().port,
        443,
        "absent port is 443"
    );
    let d = r#"{"host":"qdrant.acme.example","port":"6333","scheme":"https"}"#;
    assert_eq!(admit(d, dns.as_ref()).unwrap().port, 6333);
}

#[test]
fn a_name_resolving_to_any_private_address_is_refused() {
    for ips in [
        &["10.0.0.9"][..],
        &["127.0.0.1"],
        &["169.254.169.254"],
        &["93.184.216.34", "10.0.0.9"], // one bad answer poisons the set
        &["::1"],
        &["::ffff:10.0.0.1"],
    ] {
        let dns = FakeDns::with("qdrant.acme.example", ips);
        assert_eq!(
            admit(&doc("qdrant.acme.example", 443, "https"), dns.as_ref()),
            Err(GrantRefusal::NonPublicAddress),
            "{ips:?}"
        );
    }
    let nxdomain = Arc::new(FakeDns::default());
    assert_eq!(
        admit(&doc("qdrant.acme.example", 443, "https"), nxdomain.as_ref()),
        Err(GrantRefusal::ResolutionFailed)
    );
    let empty = FakeDns::with("qdrant.acme.example", &[]);
    assert_eq!(
        admit(&doc("qdrant.acme.example", 443, "https"), empty.as_ref()),
        Err(GrantRefusal::ResolutionFailed)
    );
}

#[test]
fn malformed_documents_are_refused() {
    let dns = public_dns();
    for d in ["", "not json", "[]", "{}", r#"{"scheme":"https"}"#] {
        assert!(admit(d, dns.as_ref()).is_err(), "{d:?}");
    }
}

#[test]
fn public_ip_classification_spot_checks() {
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ] {
        assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "100.127.255.255",
        "192.0.0.1",
        "203.0.113.9",
        "198.51.100.1",
        "240.0.0.1",
    ] {
        assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
    }
}
