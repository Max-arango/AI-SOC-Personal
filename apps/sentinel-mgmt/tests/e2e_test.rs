use std::time::Duration;

use sentinel_events::sentinel::mgmt::v1::agent_service_client::AgentServiceClient;
use sentinel_events::sentinel::mgmt::v1::{HeartbeatRequest, RegisterRequest};

use sentinel_mgmt::fleet::{AgentStatus, FleetManager};
use sentinel_mgmt::service;

#[tokio::test]
async fn test_e2e_agent_register_and_heartbeat() {
    let fleet = FleetManager::new();

    let addr = format!("127.0.0.1:{}", find_free_port());
    let serve_addr = addr.clone();
    let serve_fleet = fleet.clone();

    let server_handle = tokio::spawn(async move {
        if let Err(e) = service::serve(&serve_addr, serve_fleet).await {
            eprintln!("Server error: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = AgentServiceClient::connect(format!("http://{}", addr))
        .await
        .expect("Failed to connect to mgmt server");

    let register_resp = client
        .register(tonic::Request::new(RegisterRequest {
            host_id: "test-agent-01".into(),
            hostname: "test-host".into(),
            os: "linux".into(),
            version: "0.1.0".into(),
            tags: vec!["test".into()],
        }))
        .await
        .expect("Register failed")
        .into_inner();

    assert_eq!(register_resp.agent_id, "test-agent-01");
    assert!(register_resp.heartbeat_interval_secs > 0);

    let heartbeat_resp = client
        .heartbeat(tonic::Request::new(HeartbeatRequest {
            agent_id: "test-agent-01".into(),
            stats: None,
        }))
        .await
        .expect("Heartbeat failed")
        .into_inner();

    assert!(heartbeat_resp.acknowledged);

    let state = fleet.fleet_state();
    let agent = state
        .agents
        .iter()
        .find(|a| a.host_id == "test-agent-01")
        .expect("Agent not found in fleet");

    assert_eq!(agent.hostname, "test-host");
    assert_eq!(agent.os, "linux");
    assert!(matches!(agent.status, AgentStatus::Online));

    eprintln!("E2E test passed: agent registered, heartbeat acknowledged, fleet state correct");

    server_handle.abort();
}

#[tokio::test]
async fn test_e2e_multiple_agents() {
    let fleet = FleetManager::new();
    let addr = format!("127.0.0.1:{}", find_free_port());

    let serve_addr = addr.clone();
    let serve_fleet = fleet.clone();
    let server_handle = tokio::spawn(async move {
        let _ = service::serve(&serve_addr, serve_fleet).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    for i in 0..3 {
        let mut client = AgentServiceClient::connect(format!("http://{}", addr))
            .await
            .expect("Failed to connect");

        let _ = client
            .register(tonic::Request::new(RegisterRequest {
                host_id: format!("agent-{}", i),
                hostname: format!("host-{}", i),
                os: "linux".into(),
                version: "0.1.0".into(),
                tags: vec![],
            }))
            .await
            .expect("Register failed");

        let _ = client
            .heartbeat(tonic::Request::new(HeartbeatRequest {
                agent_id: format!("agent-{}", i),
                stats: None,
            }))
            .await
            .expect("Heartbeat failed");
    }

    let state = fleet.fleet_state();
    assert_eq!(state.agents.len(), 3);
    assert_eq!(fleet.online_count(), 3);

    eprintln!("E2E test: 3 agents registered and online");

    server_handle.abort();
}

#[tokio::test]
async fn test_e2e_heartbeat_keeps_agent_online() {
    let fleet = FleetManager::new();
    let addr = format!("127.0.0.1:{}", find_free_port());

    let serve_addr = addr.clone();
    let serve_fleet = fleet.clone();
    let server_handle = tokio::spawn(async move {
        let _ = service::serve(&serve_addr, serve_fleet).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = AgentServiceClient::connect(format!("http://{}", addr))
        .await
        .expect("Failed to connect");

    let _ = client
        .register(tonic::Request::new(RegisterRequest {
            host_id: "agent-hb".into(),
            hostname: "heartbeat-test".into(),
            os: "linux".into(),
            version: "0.1.0".into(),
            tags: vec![],
        }))
        .await
        .expect("Register failed");

    for _ in 0..5 {
        let _ = client
            .heartbeat(tonic::Request::new(HeartbeatRequest {
                agent_id: "agent-hb".into(),
                stats: None,
            }))
            .await
            .expect("Heartbeat failed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let agent = fleet
        .fleet_state()
        .agents
        .into_iter()
        .find(|a| a.host_id == "agent-hb")
        .expect("Agent not found");

    assert!(matches!(agent.status, AgentStatus::Online));
    eprintln!("E2E test: agent stays online with continuous heartbeats");

    server_handle.abort();
}

fn find_free_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    listener.local_addr().unwrap().port()
}
