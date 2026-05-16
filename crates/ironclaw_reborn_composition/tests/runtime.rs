use std::time::Duration;

use ironclaw_reborn_composition::{
    RebornBuildInput, RebornRuntimeIdentity, RebornRuntimeInput, TurnRunnerSettings,
    build_reborn_runtime,
};
use ironclaw_turns::TurnStatus;

#[tokio::test]
async fn stub_gateway_send_returns_recovery_required_without_waiting_for_poll() {
    let root = tempfile::tempdir().unwrap();
    let input = RebornRuntimeInput::from_services(RebornBuildInput::local_dev(
        "runtime-test-owner",
        root.path().join("local-dev"),
    ))
    .with_identity(RebornRuntimeIdentity {
        tenant_id: "runtime-test-tenant".to_string(),
        agent_id: "runtime-test-agent".to_string(),
        source_binding_id: "runtime-test-source".to_string(),
        reply_target_binding_id: "runtime-test-reply".to_string(),
    })
    .with_runner_settings(TurnRunnerSettings {
        heartbeat_interval: Duration::from_millis(25),
        poll_interval: Duration::from_secs(60),
    });

    let runtime = build_reborn_runtime(input).await.unwrap();
    let conversation = runtime.new_conversation().await.unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.send_user_message(&conversation, "hello"),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(reply.status, TurnStatus::RecoveryRequired);
    assert_eq!(reply.text, None);

    runtime.shutdown().await.unwrap();
}
