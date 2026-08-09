use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn check_ip_malicious() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_OTX_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_OTX_API_KEY", "test-key");

    let fixture = include_str!("fixtures/ip_malicious.json");
    Mock::given(method("GET"))
        .and(path("/api/v1/indicators/IPv4/5.5.5.5/general"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_otx::check_ip("5.5.5.5").await;

    let report = result.expect("should return report for malicious IP");
    assert!(report.pulse_count > 0);
    assert!(report.risk_score > 0);

    std::env::remove_var("SENTINEL_OTX_TEST_URL");
    std::env::remove_var("SENTINEL_OTX_API_KEY");
}

#[tokio::test]
async fn check_ip_clean() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_OTX_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_OTX_API_KEY", "test-key");

    let fixture = include_str!("fixtures/ip_clean.json");
    Mock::given(method("GET"))
        .and(path("/api/v1/indicators/IPv4/8.8.8.8/general"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_otx::check_ip("8.8.8.8").await;

    let report = result.expect("should return report for clean IP");
    assert_eq!(report.pulse_count, 0);

    std::env::remove_var("SENTINEL_OTX_TEST_URL");
    std::env::remove_var("SENTINEL_OTX_API_KEY");
}

#[tokio::test]
async fn check_ip_not_found() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_OTX_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_OTX_API_KEY", "test-key");

    Mock::given(method("GET"))
        .and(path("/api/v1/indicators/IPv4/10.0.0.99/general"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_otx::check_ip("10.0.0.99").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_OTX_TEST_URL");
    std::env::remove_var("SENTINEL_OTX_API_KEY");
}

#[tokio::test]
async fn enabled_without_key() {
    std::env::remove_var("SENTINEL_OTX_API_KEY");

    assert!(!sentinel_plugin_otx::enabled());
}
