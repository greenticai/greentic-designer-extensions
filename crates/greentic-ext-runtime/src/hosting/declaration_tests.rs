use super::*;

fn raw(endpoints: &str) -> RawDescriptor {
    RawDescriptor {
        id: "aws_ecs".into(),
        display_name: "AWS ECS".into(),
        settings_schema: r#"{"type":"object"}"#.into(),
        credential_schema: r#"{"type":"object"}"#.into(),
        endpoints: endpoints.into(),
        capabilities: r#"{"persistent-data":true,"public-https":true,"reachability":"public"}"#.into(),
        ref_prefix: "ecs:".into(),
    }
}

const ONE: &str = r#"[{"id":"aws.ecs","host":"ecs.{region}.amazonaws.com",
  "profile":{"id":"aws-sigv4","service":"ecs"},"actions":["DescribeServices","CreateService"]}]"#;

#[test]
fn a_well_formed_declaration_parses() {
    let d = HostingDeclaration::parse(&raw(ONE)).expect("valid");
    assert_eq!(d.endpoint("aws.ecs").unwrap().profile.params["service"], "ecs");
    assert!(d.endpoint("nope").is_none());
}

#[test]
fn the_hash_ignores_order_and_changes_with_anything_that_widens_authority() {
    let a = HostingDeclaration::parse(&raw(ONE)).unwrap().capability_hash();
    assert!(a.starts_with("sha256:") && a.len() == 71);
    let reordered = ONE.replace(r#"["DescribeServices","CreateService"]"#, r#"["CreateService","DescribeServices"]"#);
    assert_eq!(HostingDeclaration::parse(&raw(&reordered)).unwrap().capability_hash(), a);
    for widened in [
        ONE.replace(r#""CreateService"]"#, r#""CreateService","DeleteService"]"#),
        ONE.replace("amazonaws.com", "amazonaws.com.cn"),
        ONE.replace(r#""service":"ecs""#, r#""service":"efs""#),
        ONE.replace("aws-sigv4", "bearer"),
    ] {
        assert_ne!(HostingDeclaration::parse(&raw(&widened)).unwrap().capability_hash(), a, "{widened}");
    }
    let mut r = raw(ONE);
    r.settings_schema = r#"{"type":"object","properties":{"x":{}}}"#.into();
    assert_ne!(HostingDeclaration::parse(&r).unwrap().capability_hash(), a);
    let mut r = raw(ONE);
    r.capabilities = r#"{"persistent-data":false,"public-https":true,"reachability":"public"}"#.into();
    assert_ne!(HostingDeclaration::parse(&r).unwrap().capability_hash(), a);
}

#[test]
fn invalid_declarations_are_refused_by_name() {
    let bad: Vec<(String, &str)> = vec![
        ("[]".into(), "no endpoints"),
        (ONE.replace("aws-sigv4", "magic"), "unknown auth profile"),
        (ONE.replace("ecs.{region}.amazonaws.com", "ecs.example.com/path"), "host with a path"),
        (ONE.replace("ecs.{region}.amazonaws.com", "*.amazonaws.com"), "wildcard host"),
        (ONE.replace(r#""actions":["DescribeServices","CreateService"]"#, r#""actions":[]"#), "no actions"),
        (ONE.replace(r#""CreateService""#, r#""GET /*""#), "blanket REST rule"),
        (ONE.replace(r#""id":"aws.ecs""#, r#""id":"AWS ECS""#), "bad id"),
        (ONE.replace(r#""id":"aws.ecs","#, r#""id":"aws.ecs","extra":1,"#), "unknown field"),
        (format!("{},{}", &ONE[..ONE.len() - 1], &ONE[1..]), "duplicate id"),
    ];
    for (endpoints, why) in bad {
        assert!(HostingDeclaration::parse(&raw(&endpoints)).is_err(), "{why}");
    }
    let mut r = raw(ONE);
    r.ref_prefix = "ecs".into();
    assert!(HostingDeclaration::parse(&r).is_err());
    let mut r = raw(ONE);
    r.capabilities = r#"{"persistent-data":true,"public-https":true,"reachability":"maybe"}"#.into();
    assert!(HostingDeclaration::parse(&r).is_err());
    let mut r = raw(ONE);
    r.id = "AWS".into();
    assert!(HostingDeclaration::parse(&r).is_err());
}
