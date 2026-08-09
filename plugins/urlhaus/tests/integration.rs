use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn check_url_malicious() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_URLHAUS_TEST_URL", &mock_url);

    let fixture = include_str!("fixtures/url_malicious.json");
    Mock::given(method("POST"))
        .and(path("/v1/url/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_urlhaus::check_url("http://malware.example.com/bad.exe").await;

    let report = result.expect("should return report for malicious URL");
    assert!(report.is_malicious);
    assert!(report.risk_score > 0);

    std::env::remove_var("SENTINEL_URLHAUS_TEST_URL");
}

#[tokio::test]
async fn check_url_clean() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_URLHAUS_TEST_URL", &mock_url);

    let fixture = include_str!("fixtures/url_clean.json");
    Mock::given(method("POST"))
        .and(path("/v1/url/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_urlhaus::check_url("http://clean.example.com").await;

    let report = result.expect("should return report for clean URL");
    assert!(!report.is_malicious);

    std::env::remove_var("SENTINEL_URLHAUS_TEST_URL");
}

#[tokio::test]
async fn check_url_unknown() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_URLHAUS_TEST_URL", &mock_url);

    let fixture = include_str!("fixtures/url_unknown.json");
    Mock::given(method("POST"))
        .and(path("/v1/url/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_urlhaus::check_url("http://never-seen.example.com").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_URLHAUS_TEST_URL");
}

#[test]
fn url_report_fields_populated() {
    let report = sentinel_plugin_urlhaus::UrlReport {
        url: "http://malware.example.com/bad.exe".into(),
        status: "online".into(),
        threat: "malware_download".into(),
        tags: vec!["exe".into(), "emotet".into()],
        reference: "https://urlhaus.abuse.ch/url/123/".into(),
        is_malicious: true,
        risk_score: 80,
    };
    assert_eq!(report.status, "online");
    assert_eq!(report.threat, "malware_download");
    assert_eq!(report.tags.len(), 2);
    assert!(report.is_malicious);
}
