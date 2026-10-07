//! `host.http.fetch` redirect handling: what a hop carries forward.
//!
//! The host follows redirects itself so it can re-check the allow-list at
//! every hop. These tests pin what each hop SENDS: a credential the guest set
//! for one origin must not travel to another (an API key for `fal.run` must not
//! reach a CDN host it redirects to), and a 301/302/303 after a non-GET turns
//! into a body-less GET, as a browser and reqwest both do.
//!
//! Two `wiremock` servers on different ports are two origins (the port is part
//! of the origin). The client is built with `redirect::Policy::none()` so the
//! host's own loop is what is exercised.
use greentic_ext_runtime::host_bindings::greentic::extension_host::http::{
    Host as HttpHost, Request,
};
use greentic_ext_runtime::{HostState, UrlMatcher, reqwest};
use greentic_extension_sdk_contract::describe::Permissions;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET_HEADERS: [(&str, &str); 3] = [
    ("Authorization", "Key sk-live-secret"),
    ("Cookie", "session=abc"),
    ("Proxy-Authorization", "Basic cHJveHk="),
];

fn host_for(patterns: Vec<String>) -> HostState {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    HostState::builder("redirect-test".into(), Permissions::default())
        .url_matcher(UrlMatcher::from_patterns(patterns).with_allow_http(true))
        .http_client(Some(client))
        .build()
}

fn pattern(server: &MockServer) -> String {
    format!("{}/*", server.uri())
}

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Runs `fetch` on a blocking thread. The host (and its blocking reqwest
/// client, which owns a runtime of its own) is built and dropped there too:
/// dropping it from an async context panics.
async fn fetch(patterns: Vec<String>, req: Request) -> Result<u16, String> {
    tokio::task::spawn_blocking(move || host_for(patterns).fetch(req).map(|r| r.status))
        .await
        .expect("fetch thread")
}

async fn redirect_from(source: &MockServer, status: u16, to: String) {
    Mock::given(path("/start"))
        .respond_with(ResponseTemplate::new(status).insert_header("Location", to.as_str()))
        .mount(source)
        .await;
}

async fn land(target: &MockServer) {
    Mock::given(path("/landing"))
        .respond_with(ResponseTemplate::new(200))
        .mount(target)
        .await;
}

async fn landing_request(target: &MockServer) -> wiremock::Request {
    let received = target.received_requests().await.expect("recording on");
    let mut landed: Vec<_> = received
        .into_iter()
        .filter(|r| r.url.path() == "/landing")
        .collect();
    assert_eq!(landed.len(), 1, "expected exactly one landing request");
    landed.remove(0)
}

fn has(req: &wiremock::Request, name: &str) -> bool {
    req.headers.contains_key(name)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cross_origin_redirect_drops_credential_headers() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    redirect_from(&a, 302, format!("{}/landing", b.uri())).await;
    land(&b).await;

    let mut sent = headers(&SECRET_HEADERS);
    sent.push(("X-Trace".into(), "keep-me".into()));
    let req = Request {
        method: "GET".into(),
        url: format!("{}/start", a.uri()),
        headers: sent,
        body: None,
    };
    let status = fetch(vec![pattern(&a), pattern(&b)], req)
        .await
        .expect("fetch");
    assert_eq!(status, 200);

    let landed = landing_request(&b).await;
    for (name, _) in SECRET_HEADERS {
        assert!(!has(&landed, name), "{name} crossed origins");
    }
    assert!(
        has(&landed, "x-trace"),
        "a non-credential header was dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_header_names_are_matched_case_insensitively() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    redirect_from(&a, 307, format!("{}/landing", b.uri())).await;
    land(&b).await;

    let req = Request {
        method: "GET".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&[
            ("aUtHoRiZaTiOn", "Bearer t"),
            ("COOKIE", "s=1"),
            ("proxy-AUTHORIZATION", "Basic x"),
            ("X-Api-KEY", "k"),
        ]),
        body: None,
    };
    fetch(vec![pattern(&a), pattern(&b)], req)
        .await
        .expect("fetch");

    let landed = landing_request(&b).await;
    for name in [
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
    ] {
        assert!(!has(&landed, name), "{name} crossed origins");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_origin_redirect_keeps_credential_headers() {
    let a = MockServer::start().await;
    redirect_from(&a, 302, format!("{}/landing", a.uri())).await;
    land(&a).await;

    let req = Request {
        method: "GET".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&SECRET_HEADERS),
        body: None,
    };
    fetch(vec![pattern(&a)], req).await.expect("fetch");

    let landed = landing_request(&a).await;
    for (name, value) in SECRET_HEADERS {
        let got = landed.headers.get(name).map(|v| v.to_str().unwrap_or(""));
        assert_eq!(got, Some(value), "{name} lost on a same-origin hop");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_followed_by_302_becomes_a_get_without_a_body() {
    let a = MockServer::start().await;
    redirect_from(&a, 302, format!("{}/landing", a.uri())).await;
    land(&a).await;

    let req = Request {
        method: "POST".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer t"),
        ]),
        body: Some(br#"{"prompt":"x"}"#.to_vec()),
    };
    fetch(vec![pattern(&a)], req).await.expect("fetch");

    let landed = landing_request(&a).await;
    assert_eq!(landed.method.as_str(), "GET");
    assert!(landed.body.is_empty(), "the POST body was re-sent");
    assert!(!has(&landed, "content-type"), "content-type kept");
    assert!(!has(&landed, "content-length") || landed.headers["content-length"] == "0");
    // Same origin: the method change does not cost the credential.
    assert!(has(&landed, "authorization"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_followed_by_303_becomes_a_get_without_a_body() {
    let a = MockServer::start().await;
    redirect_from(&a, 303, format!("{}/landing", a.uri())).await;
    land(&a).await;

    let req = Request {
        method: "PUT".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&[("Content-Type", "text/plain")]),
        body: Some(b"payload".to_vec()),
    };
    fetch(vec![pattern(&a)], req).await.expect("fetch");

    let landed = landing_request(&a).await;
    assert_eq!(landed.method.as_str(), "GET");
    assert!(landed.body.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_307_keeps_method_and_body_but_not_credentials_across_origins() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    redirect_from(&a, 307, format!("{}/landing", b.uri())).await;
    land(&b).await;

    let req = Request {
        method: "POST".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer t"),
        ]),
        body: Some(br#"{"prompt":"x"}"#.to_vec()),
    };
    fetch(vec![pattern(&a), pattern(&b)], req)
        .await
        .expect("fetch");

    let landed = landing_request(&b).await;
    assert_eq!(landed.method.as_str(), "POST");
    assert_eq!(landed.body, br#"{"prompt":"x"}"#.to_vec());
    assert!(
        has(&landed, "content-type"),
        "a 307 must keep its content-type"
    );
    assert!(
        !has(&landed, "authorization"),
        "authorization crossed origins"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_off_the_allow_list_is_still_refused() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    redirect_from(&a, 302, format!("{}/landing", b.uri())).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&b)
        .await;

    let req = Request {
        method: "GET".into(),
        url: format!("{}/start", a.uri()),
        headers: headers(&SECRET_HEADERS),
        body: None,
    };
    let err = fetch(vec![pattern(&a)], req)
        .await
        .expect_err("hop off the allow-list must fail");
    assert!(
        err.contains("not allowed for redirect target"),
        "got: {err}"
    );
    let received = b.received_requests().await.expect("recording on");
    assert!(received.is_empty(), "the off-list host was contacted");
}
