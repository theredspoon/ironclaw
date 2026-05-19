#[allow(dead_code)]
#[path = "support/reborn/mod.rs"]
mod reborn_support;
mod support;

use ironclaw_product_adapters::ProductInboundAck;
use ironclaw_turns::TurnStatus;
use reborn_support::harness::RebornBinaryE2EHarness;

#[tokio::test]
async fn reborn_minimal_dispatch_parity() {
    let mut harness =
        RebornBinaryE2EHarness::reply_only("room-minimal-dispatch", "minimal dispatch complete")
            .await
            .expect("harness");
    harness.start();

    let submitted = harness
        .submit_text("event-minimal-dispatch", "ping")
        .await
        .expect("submit text");
    assert!(matches!(submitted.ack, ProductInboundAck::Accepted { .. }));

    harness
        .wait_for_status(submitted.run_id, TurnStatus::Completed)
        .await
        .expect("completed run");
    harness
        .assert_final_reply("minimal dispatch complete")
        .await
        .expect("final reply");
    assert_eq!(harness.model_requests().len(), 1);

    harness.shutdown().await;
}
