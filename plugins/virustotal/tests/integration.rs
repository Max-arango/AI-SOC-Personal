use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn lookup_hash_malicious() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_VIRUSTOTAL_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_VIRUSTOTAL_API_KEY", "test-key");

    let fixture = include_str!("fixtures/hash_malicious.json");
    Mock::given(method("GET"))
        .and(path("/api/v3/files/d41d8cd98f00b204e9800998ecf8427ebadcafe"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result =
        sentinel_plugin_virustotal::lookup_hash("d41d8cd98f00b204e9800998ecf8427ebadcafe").await;

    let report = result.expect("should return report for malicious hash");
    assert!(report.malicious > 0);

    std::env::remove_var("SENTINEL_VIRUSTOTAL_TEST_URL");
    std::env::remove_var("SENTINEL_VIRUSTOTAL_API_KEY");
}

#[tokio::test]
async fn lookup_hash_clean() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_VIRUSTOTAL_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_VIRUSTOTAL_API_KEY", "test-key");

    let fixture = include_str!("fixtures/hash_clean.json");
    Mock::given(method("GET"))
        .and(path(
            "/api/v3/files/aabbccdd11223344556677889900aabbccddeeff",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result =
        sentinel_plugin_virustotal::lookup_hash("aabbccdd11223344556677889900aabbccddeeff").await;

    let report = result.expect("should return report for clean hash");
    assert_eq!(report.malicious, 0);

    std::env::remove_var("SENTINEL_VIRUSTOTAL_TEST_URL");
    std::env::remove_var("SENTINEL_VIRUSTOTAL_API_KEY");
}

#[tokio::test]
async fn lookup_hash_not_found() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_VIRUSTOTAL_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_VIRUSTOTAL_API_KEY", "test-key");

    let fixture = include_str!("fixtures/hash_not_found.json");
    Mock::given(method("GET"))
        .and(path("/api/v3/files/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
        .respond_with(ResponseTemplate::new(404).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result =
        sentinel_plugin_virustotal::lookup_hash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_VIRUSTOTAL_TEST_URL");
    std::env::remove_var("SENTINEL_VIRUSTOTAL_API_KEY");
}

#[tokio::test]
async fn lookup_hash_api_error() {
    let mock_server = MockServer::start().await;
    let mock_url = mock_server.uri();

    std::env::set_var("SENTINEL_VIRUSTOTAL_TEST_URL", &mock_url);
    std::env::set_var("SENTINEL_VIRUSTOTAL_API_KEY", "test-key");

    let fixture = include_str!("fixtures/hash_not_found.json");
    Mock::given(method("GET"))
        .and(path("/api/v3/files/errorhash0000000000000000000000000000"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture))
        .mount(&mock_server)
        .await;

    let result =
        sentinel_plugin_virustotal::lookup_hash("errorhash0000000000000000000000000000").await;

    assert!(result.is_none());

    std::env::remove_var("SENTINEL_VIRUSTOTAL_TEST_URL");
    std::env::remove_var("SENTINEL_VIRUSTOTAL_API_KEY");
}

#[tokio::test]
async fn enabled_without_key() {
    std::env::remove_var("SENTINEL_VIRUSTOTAL_API_KEY");

    assert!(!sentinel_plugin_virustotal::enabled());
}
