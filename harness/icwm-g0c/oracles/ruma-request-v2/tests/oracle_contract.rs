use std::{borrow::Cow, collections::BTreeMap, time::Duration};

use ruma_client_api::{
    backup::{
        BackupAlgorithm, KeyBackupData, add_backup_keys, add_backup_keys_for_room,
        add_backup_keys_for_session, create_backup_version, delete_backup_version, get_backup_info,
        get_backup_keys, get_backup_keys_for_room, get_backup_keys_for_session,
        get_latest_backup_info, update_backup_version,
    },
    device::get_devices,
    keys::{claim_keys, get_key_changes, get_keys, upload_keys},
    sync::sync_events,
};
use ruma_common::{
    OneTimeKeyAlgorithm,
    api::{
        EndpointError as _, IncomingResponse as _, MatrixVersion, OutgoingRequestExt as _,
        SupportedVersions,
        auth_scheme::SendAccessToken,
        error::{Error, ErrorKind, FromHttpResponseError, RetryAfter},
    },
    owned_device_id, owned_room_id, owned_user_id,
    serde::Raw,
};
use serde_json::Value;

fn versions() -> Cow<'static, SupportedVersions> {
    Cow::Owned(SupportedVersions {
        versions: [MatrixVersion::V1_19].into(),
        features: Default::default(),
    })
}

fn vectors() -> BTreeMap<String, Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/REQUEST-VECTORS-v2.json"
    );
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| {
            (
                vector["operation"].as_str().unwrap().to_owned(),
                vector.clone(),
            )
        })
        .collect()
}

fn assert_request(vector: &Value, request: http::Request<Vec<u8>>) {
    assert_eq!(request.method().as_str(), vector["request"]["method"]);
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        vector["request"]["encoded_uri"]
    );
    assert_eq!(
        request.headers().get("authorization").unwrap(),
        "Bearer oracle-only"
    );
    let expected_body = &vector["request"]["body"];
    if expected_body.is_null() {
        assert!(request.body().is_empty() || request.body() == b"{}");
    } else {
        assert_eq!(
            serde_json::from_slice::<Value>(request.body()).unwrap(),
            *expected_body
        );
    }
}

#[test]
fn pinned_ruma_constructs_published_backup_get_and_delete_requests() {
    let vectors = vectors();
    let token = || SendAccessToken::IfRequired("oracle-only");

    assert_request(
        &vectors["room_key_backup_version_get_current"],
        get_latest_backup_info::v3::Request::new()
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_key_backup_version_get"],
        get_backup_info::v3::Request::new("v 1".into())
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_key_backup_version_delete"],
        delete_backup_version::v3::Request::new("v 1".into())
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_keys_get_all"],
        get_backup_keys::v3::Request::new("v 1".into())
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_keys_get_room"],
        get_backup_keys_for_room::v3::Request::new(
            "v 1".into(),
            owned_room_id!("!room:example.org"),
        )
        .try_into_http_request("https://example.org", token(), versions())
        .unwrap(),
    );
    assert_request(
        &vectors["room_keys_get_session"],
        get_backup_keys_for_session::v3::Request::new(
            "v 1".into(),
            owned_room_id!("!room:example.org"),
            "session /1".into(),
        )
        .try_into_http_request("https://example.org", token(), versions())
        .unwrap(),
    );
}

fn raw<T>(value: &Value) -> Raw<T> {
    Raw::from_json_string(serde_json::to_string(value).unwrap()).unwrap()
}

#[test]
fn pinned_ruma_constructs_published_backup_write_requests() {
    let vectors = vectors();
    let token = || SendAccessToken::IfRequired("oracle-only");

    let create_body = &vectors["room_key_backup_version_create"]["request"]["body"];
    assert_request(
        &vectors["room_key_backup_version_create"],
        create_backup_version::v3::Request::new(raw::<BackupAlgorithm>(create_body))
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    let update_body = &vectors["room_key_backup_version_update"]["request"]["body"];
    assert_request(
        &vectors["room_key_backup_version_update"],
        update_backup_version::v3::Request::new("v 1".into(), raw::<BackupAlgorithm>(update_body))
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_keys_put_all"],
        add_backup_keys::v3::Request::new("v 1".into(), BTreeMap::new())
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
    assert_request(
        &vectors["room_keys_put_room"],
        add_backup_keys_for_room::v3::Request::new(
            "v 1".into(),
            owned_room_id!("!room:example.org"),
            BTreeMap::new(),
        )
        .try_into_http_request("https://example.org", token(), versions())
        .unwrap(),
    );
    let session_body = &vectors["room_keys_put_session"]["request"]["body"];
    assert_request(
        &vectors["room_keys_put_session"],
        add_backup_keys_for_session::v3::Request::new(
            "v 1".into(),
            owned_room_id!("!room:example.org"),
            "session /1".into(),
            raw::<KeyBackupData>(session_body),
        )
        .try_into_http_request("https://example.org", token(), versions())
        .unwrap(),
    );
}

#[test]
fn pinned_ruma_constructs_published_sync_device_and_key_requests() {
    let vectors = vectors();
    let token = || SendAccessToken::IfRequired("oracle-only");

    let mut sync = sync_events::v3::Request::new();
    sync.since = Some("s0".into());
    sync.timeout = Some(Duration::from_millis(30_000));
    assert_request(
        &vectors["sync"],
        sync.try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );

    assert_request(
        &vectors["device_list"],
        get_devices::v3::Request::new()
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );

    let mut query = get_keys::v3::Request::new();
    query
        .device_keys
        .insert(owned_user_id!("@alice:example.org"), Vec::new());
    assert_request(
        &vectors["keys_query"],
        query
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );

    let mut claim = claim_keys::v3::Request::new(BTreeMap::from([(
        owned_user_id!("@alice:example.org"),
        BTreeMap::from([(
            owned_device_id!("ALICE"),
            OneTimeKeyAlgorithm::SignedCurve25519,
        )]),
    )]));
    claim.timeout = None;
    assert_request(
        &vectors["keys_claim"],
        claim
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );

    assert_request(
        &vectors["keys_upload"],
        upload_keys::v3::Request::new()
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );

    assert_request(
        &vectors["keys_changes"],
        get_key_changes::v3::Request::new("s0".into(), "s1".into())
            .try_into_http_request("https://example.org", token(), versions())
            .unwrap(),
    );
}

#[test]
fn pinned_ruma_decodes_published_backup_success_and_matrix_error_shapes() {
    let vectors = vectors();
    let response = |operation: &str, index: usize| {
        let case = &vectors[operation]["responses"][index];
        let mut builder = http::Response::builder().status(case["status"].as_u64().unwrap() as u16);
        for header in case["headers"].as_array().unwrap() {
            builder = builder.header(
                header["name"].as_str().unwrap(),
                header["value"].as_str().unwrap(),
            );
        }
        builder
            .body(serde_json::to_vec(&case["body"]).unwrap())
            .unwrap()
    };

    delete_backup_version::v3::Response::try_from_http_response(response(
        "room_key_backup_version_delete",
        0,
    ))
    .unwrap();
    get_backup_keys::v3::Response::try_from_http_response(response("room_keys_get_all", 0))
        .unwrap();
    get_backup_keys_for_room::v3::Response::try_from_http_response(response(
        "room_keys_get_room",
        0,
    ))
    .unwrap();
    get_backup_keys_for_session::v3::Response::try_from_http_response(response(
        "room_keys_get_session",
        0,
    ))
    .unwrap();

    let wrong_version = delete_backup_version::v3::Response::try_from_http_response(response(
        "room_key_backup_version_delete",
        1,
    ))
    .unwrap_err();
    match wrong_version {
        FromHttpResponseError::Server(error) => match error.error_kind() {
            Some(ErrorKind::WrongRoomKeysVersion(data)) => {
                assert_eq!(data.current_version, "v 2")
            }
            other => panic!("unexpected Matrix error kind: {other:?}"),
        },
        other => panic!("unexpected response error: {other:?}"),
    }

    let rate = Error::from_http_response(response("room_key_backup_version_delete", 2));
    match rate.error_kind() {
        Some(ErrorKind::LimitExceeded(data)) => match &data.retry_after {
            Some(RetryAfter::Delay(delay)) => assert_eq!(delay.as_millis(), 120_000),
            other => panic!("unexpected retry delay: {other:?}"),
        },
        other => panic!("unexpected rate-limit error kind: {other:?}"),
    }
}
