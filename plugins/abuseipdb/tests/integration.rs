use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn check_ip_malicious() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_ABUSEIPDB_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_ABUSEIPDB_API_KEY", "test-key");

    let fixture = include_str!("fixtures/ip_malicious.json");
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .and(query_param("ipAddress", "1.2.3.4"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_abuseipdb::check_ip("1.2.3.4").await;

    let report = result.expect("should return report for malicious IP");
    assert_eq!(report.abuse_score, 95);
    assert_eq!(report.total_reports, 42);
    assert_eq!(
        report.risk_level,
        sentinel_plugin_abuseipdb::RiskLevel::Critical
    );

    std::env::remove_var("SENTINEL_ABUSEIPDB_TEST_URL");
    std::env::remove_var("SENTINEL_ABUSEIPDB_API_KEY");
}

#[tokio::test]
async fn check_ip_clean() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_ABUSEIPDB_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_ABUSEIPDB_API_KEY", "test-key");

    let fixture = include_str!("fixtures/ip_clean.json");
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .and(query_param("ipAddress", "8.8.8.8"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_abuseipdb::check_ip("8.8.8.8").await;

    let report = result.expect("should return report for clean IP");
    assert_eq!(report.abuse_score, 0);
    assert_eq!(report.risk_level, sentinel_plugin_abuseipdb::RiskLevel::Safe);

    std::env::remove_var("SENTINEL_ABUSEIPDB_TEST_URL");
    std::env::remove_var("SENTINEL_ABUSEIPDB_API_KEY");
}

#[tokio::test]
async fn check_ip_api_error() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_ABUSEIPDB_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_ABUSEIPDB_API_KEY", "test-key");

    let fixture = include_str!("fixtures/ip_error.json");
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_abuseipdb::check_ip("9.9.9.9").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_ABUSEIPDB_TEST_URL");
    std::env::remove_var("SENTINEL_ABUSEIPDB_API_KEY");
}

#[tokio::test]
async fn check_ip_server_error() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_ABUSEIPDB_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_ABUSEIPDB_API_KEY", "test-key");

    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let result = sentinel_plugin_abuseipdb::check_ip("10.10.10.10").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_ABUSEIPDB_TEST_URL");
    std::env::remove_var("SENTINEL_ABUSEIPDB_API_KEY");
}

#[tokio::test]
async fn enabled_without_key() {
    std::env::remove_var("SENTINEL_ABUSEIPDB_API_KEY");

    assert!(!sentinel_plugin_abuseipdb::enabled());
}
