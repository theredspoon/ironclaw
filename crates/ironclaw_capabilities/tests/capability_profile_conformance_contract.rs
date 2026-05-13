use ironclaw_capabilities::{
    CapabilityProfileClaim, CapabilityProfileClaimedOperation, CapabilityProfileConformanceFinding,
    CapabilityProfileConformanceFindingKind, CapabilityProfileConformanceReport,
};
use ironclaw_host_api::{
    CapabilityId, CapabilityProfileContract, CapabilityProfileId,
    CapabilityProfileOperationContract, CapabilityProfileOperationId,
};

#[test]
fn capability_profile_conformance_reports_missing_required_operations() {
    let contract = context_retrieval_contract();
    let claim = CapabilityProfileClaim::new(
        CapabilityId::new("ironclaw.memory.native.context.retrieve").unwrap(),
        CapabilityProfileId::new("memory.context_retrieval.v1").unwrap(),
        Vec::new(),
    )
    .unwrap();

    let report = CapabilityProfileConformanceReport::evaluate(&contract, &claim);

    assert!(!report.is_conformant());
    assert_eq!(
        report.findings(),
        &[CapabilityProfileConformanceFinding::new(
            CapabilityProfileConformanceFindingKind::MissingRequiredOperation,
            "memory.context.retrieve.v1",
        )]
    );
}

#[test]
fn capability_profile_conformance_reports_schema_mismatches_and_extra_operations() {
    let contract = context_retrieval_contract();
    let claim = CapabilityProfileClaim::new(
        CapabilityId::new("ironclaw.memory.native.context.retrieve").unwrap(),
        CapabilityProfileId::new("memory.context_retrieval.v1").unwrap(),
        vec![
            CapabilityProfileClaimedOperation::new(
                CapabilityProfileOperationId::new("memory.context.retrieve.v1").unwrap(),
                "schemas/memory/wrong.input.v1.json",
                "schemas/memory/context-retrieve.output.v1.json",
            )
            .unwrap(),
            CapabilityProfileClaimedOperation::new(
                CapabilityProfileOperationId::new("memory.context.extra.v1").unwrap(),
                "schemas/memory/extra.input.v1.json",
                "schemas/memory/extra.output.v1.json",
            )
            .unwrap(),
        ],
    )
    .unwrap();

    let report = CapabilityProfileConformanceReport::evaluate(&contract, &claim);

    assert!(!report.is_conformant());
    assert_eq!(
        report.findings(),
        &[
            CapabilityProfileConformanceFinding::new(
                CapabilityProfileConformanceFindingKind::InputSchemaRefMismatch,
                "memory.context.retrieve.v1",
            ),
            CapabilityProfileConformanceFinding::new(
                CapabilityProfileConformanceFindingKind::UnexpectedOperation,
                "memory.context.extra.v1",
            ),
        ]
    );
}

#[test]
fn capability_profile_conformance_accepts_matching_claims() {
    let contract = context_retrieval_contract();
    let claim = CapabilityProfileClaim::new(
        CapabilityId::new("ironclaw.memory.native.context.retrieve").unwrap(),
        CapabilityProfileId::new("memory.context_retrieval.v1").unwrap(),
        vec![
            CapabilityProfileClaimedOperation::new(
                CapabilityProfileOperationId::new("memory.context.retrieve.v1").unwrap(),
                "schemas/memory/context-retrieve.input.v1.json",
                "schemas/memory/context-retrieve.output.v1.json",
            )
            .unwrap(),
        ],
    )
    .unwrap();

    let report = CapabilityProfileConformanceReport::evaluate(&contract, &claim);

    assert!(report.is_conformant());
    assert!(report.findings().is_empty());
}

fn context_retrieval_contract() -> CapabilityProfileContract {
    CapabilityProfileContract::new(
        CapabilityProfileId::new("memory.context_retrieval.v1").unwrap(),
        vec![
            CapabilityProfileOperationContract::new(
                CapabilityProfileOperationId::new("memory.context.retrieve.v1").unwrap(),
                "schemas/memory/context-retrieve.input.v1.json",
                "schemas/memory/context-retrieve.output.v1.json",
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
