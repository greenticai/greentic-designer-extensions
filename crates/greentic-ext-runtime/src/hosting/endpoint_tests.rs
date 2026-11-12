use super::*;

fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn wildcard_hosts_need_a_label_and_a_dot_boundary() {
    assert!(host_matches("*.amazonaws.com", "ecs.eu-west-1.amazonaws.com"));
    assert!(host_matches("*.amazonaws.com", "ecs.amazonaws.com:443"));
    assert!(!host_matches("*.amazonaws.com", "amazonaws.com"));
    assert!(!host_matches("*.amazonaws.com", "evil-amazonaws.com"));
    assert!(!host_matches("*.amazonaws.com", "amazonaws.com.evil.net"));
    assert!(host_matches("api.example.com", "api.example.com"));
    assert!(!host_matches("api.example.com", "x.api.example.com"));
}

#[test]
fn host_templates_resolve_only_to_well_formed_hosts() {
    let ok = |k: &str| (k == "region").then(|| "eu-west-1".to_string());
    assert_eq!(
        resolve_host("ecs.{region}.amazonaws.com", ok).as_deref(),
        Some("ecs.eu-west-1.amazonaws.com")
    );
    for evil in ["x.evil.com/", "a@b.com", "ex ample", "A.B", "a..b", "", "-a.com"] {
        let setting = |_: &str| Some(evil.to_string());
        assert!(
            resolve_host("{region}.amazonaws.com", setting).is_none(),
            "{evil:?} must not resolve"
        );
    }
    assert!(resolve_host("ecs.{missing}.com", |_| None).is_none());
}

#[test]
fn private_and_metadata_hosts_are_recognised() {
    for private in [
        "localhost",
        "10.1.2.3",
        "192.168.0.1",
        "169.254.169.254",
        "127.0.0.1:8080",
        "100.64.0.1",
        "svc.internal",
        "intranet",
        "0x7f.0.0.1",
        "2130706433",
    ] {
        assert!(is_private_host(private), "{private}");
    }
    for public in ["ecs.eu-west-1.amazonaws.com", "run.googleapis.com", "8.8.8.8"] {
        assert!(!is_private_host(public), "{public}");
    }
}

#[test]
fn paths_cannot_carry_an_authority_or_a_traversal() {
    assert_eq!(validate_path("/v1/x?a=b"), Ok("/v1/x"));
    for bad in [
        "",
        "v1/x",
        "//evil.com/x",
        "/a/../b",
        "/a/%2e%2E/b",
        "/https://evil.com",
        "/a\\b",
        "/a\nb",
        "/a#frag",
    ] {
        assert!(validate_path(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn only_allow_listed_headers_pass() {
    assert!(validate_headers(&h(&[("Content-Type", "application/json")])).is_ok());
    for bad in ["authorization", "Cookie", "host", "x-amz-security-token", "x-api-key"] {
        assert!(validate_headers(&h(&[(bad, "v")])).is_err(), "{bad}");
    }
    assert!(validate_headers(&h(&[("accept", "a\r\nb")])).is_err());
}

#[test]
fn the_service_action_comes_from_the_target_header_or_the_form_field() {
    let t = h(&[("x-amz-target", "AmazonEC2ContainerServiceV20141113.DescribeServices")]);
    assert_eq!(derive_action(&t, None).as_deref(), Some("DescribeServices"));
    let f = h(&[("content-type", "application/x-www-form-urlencoded")]);
    assert_eq!(
        derive_action(&f, Some(b"Action=DescribeRules&Version=2015-12-01")).as_deref(),
        Some("DescribeRules")
    );
    assert_eq!(derive_action(&h(&[]), Some(b"Action=X")), None);
}

#[test]
fn action_rules_match_service_names_and_rest_prefixes() {
    let actions = vec![
        "DescribeServices".to_string(),
        "GET /api/v1/namespaces/*".to_string(),
        "POST /api/v1/ping".to_string(),
    ];
    assert!(action_allowed(&actions, "POST", "/", Some("DescribeServices")));
    assert!(!action_allowed(&actions, "POST", "/", Some("DeleteService")));
    assert!(!action_allowed(&actions, "POST", "/", None));
    assert!(action_allowed(&actions, "GET", "/api/v1/namespaces/x/pods", None));
    assert!(!action_allowed(&actions, "DELETE", "/api/v1/namespaces/x", None));
    assert!(action_allowed(&actions, "POST", "/api/v1/ping", None));
    assert!(!action_allowed(&actions, "POST", "/api/v1/ping/more", None));
}

#[test]
fn rule_syntax_refuses_blanket_grants() {
    assert!(ActionRule::parse("GET /*").is_err());
    assert!(ActionRule::parse("FETCH /x").is_err());
    assert!(ActionRule::parse("GET /a*b").is_err());
    assert!(ActionRule::parse("*").is_err());
    assert!(ActionRule::parse("Describe Services").is_err());
    assert!(ActionRule::parse("DescribeServices").is_ok());
}

#[test]
fn host_templates_reject_structure() {
    for bad in ["a.com/x", "a@b.com", "*.a.com", "A.com", "a b", "{a{b}}", "a}", "{a"] {
        assert!(validate_host_template(bad).is_err(), "{bad}");
    }
    assert!(validate_host_template("ecs.{region}.amazonaws.com").is_ok());
    assert!(validate_host_template("{api_server}").is_ok());
}
