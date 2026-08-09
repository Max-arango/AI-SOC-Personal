use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn lookup_host_exposed() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_SHODAN_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_SHODAN_API_KEY", "test-key");

    let fixture = include_str!("fixtures/host_exposed.json");
    Mock::given(method("GET"))
        .and(path("/shodan/host/192.168.1.100"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_shodan::lookup_host("192.168.1.100").await;

    let report = result.expect("should return report for exposed host");
    assert!(report.open_ports.contains(&22));
    assert!(!report.vulnerabilities.is_empty());
    assert!(report.risk_score > 0);

    std::env::remove_var("SENTINEL_SHODAN_TEST_URL");
    std::env::remove_var("SENTINEL_SHODAN_API_KEY");
}

#[tokio::test]
async fn lookup_host_not_found() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_SHODAN_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_SHODAN_API_KEY", "test-key");

    let fixture = include_str!("fixtures/host_not_found.json");
    Mock::given(method("GET"))
        .and(path("/shodan/host/10.0.0.1"))
        .respond_with(ResponseTemplate::new(404).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_shodan::lookup_host("10.0.0.1").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_SHODAN_TEST_URL");
    std::env::remove_var("SENTINEL_SHODAN_API_KEY");
}

#[tokio::test]
async fn lookup_host_server_error() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_SHODAN_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_SHODAN_API_KEY", "test-key");

    Mock::given(method("GET"))
        .and(path("/shodan/host/10.0.0.2"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_shodan::lookup_host("10.0.0.2").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_SHODAN_TEST_URL");
    std::env::remove_var("SENTINEL_SHODAN_API_KEY");
}

#[tokio::test]
async fn enabled_without_key() {
    std::env::remove_var("SENTINEL_SHODAN_API_KEY");

    assert!(!sentinel_plugin_shodan::enabled());
}
