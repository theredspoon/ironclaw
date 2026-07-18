use super::*;

#[derive(Debug, Clone)]
pub struct MatrixHttpDeliveryEndpoint {
    homeserver_origin: String,
    scheme: NetworkScheme,
    host: String,
    port: Option<u16>,
    credential_secret: SecretHandle,
    credential_handle_fingerprint: String,
    capability_id: CapabilityId,
    response_body_limit: u64,
    timeout_ms: Option<u32>,
}

impl MatrixHttpDeliveryEndpoint {
    pub fn new(
        homeserver_origin: impl Into<String>,
        credential_secret: SecretHandle,
        credential_handle_fingerprint: impl Into<String>,
        capability_id: CapabilityId,
    ) -> Result<Self, DeliveryError> {
        let homeserver_origin = homeserver_origin.into();
        let (scheme, host, port) = parse_matrix_homeserver_origin(&homeserver_origin)?;
        let credential_handle_fingerprint = credential_handle_fingerprint.into();
        if !is_canonical_sha256_fingerprint(&credential_handle_fingerprint) {
            return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
        }
        Ok(Self {
            homeserver_origin: canonical_matrix_homeserver_origin(scheme, &host, port),
            scheme,
            host,
            port,
            credential_secret,
            credential_handle_fingerprint,
            capability_id,
            response_body_limit: 4096,
            timeout_ms: Some(10_000),
        })
    }

    pub fn with_response_body_limit(
        mut self,
        response_body_limit: u64,
    ) -> Result<Self, DeliveryError> {
        if !(256..=16 * 1024 * 1024).contains(&response_body_limit) {
            return Err(DeliveryError::new(DeliveryReasonCode::MatrixBadRequest));
        }
        self.response_body_limit = response_body_limit;
        Ok(self)
    }

    pub fn with_timeout_ms(mut self, timeout_ms: Option<u32>) -> Result<Self, DeliveryError> {
        if let Some(timeout_ms) = timeout_ms
            && !(100..=120_000).contains(&timeout_ms)
        {
            return Err(DeliveryError::new(DeliveryReasonCode::MatrixBadRequest));
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    pub fn homeserver_origin_fingerprint(&self) -> String {
        redacted_sha256_fingerprint(self.homeserver_origin.as_bytes())
    }

    pub fn credential_handle_fingerprint(&self) -> &str {
        &self.credential_handle_fingerprint
    }

    pub(crate) fn credential_secret(&self) -> &SecretHandle {
        &self.credential_secret
    }
}

#[async_trait]
pub trait MatrixHttpCredentialMaterialProvider: Send + Sync {
    async fn resolve_matrix_credential_material(
        &self,
        scope: &ResourceScope,
        endpoint: &MatrixHttpDeliveryEndpoint,
    ) -> Result<HostRuntimeCredentialMaterial, DeliveryError>;
}

pub struct MatrixSecretStoreCredentialMaterialProvider {
    secret_store: Arc<dyn SecretStore>,
}

impl MatrixSecretStoreCredentialMaterialProvider {
    #[cfg(any(test, feature = "libsql", feature = "postgres"))]
    pub(crate) fn new(secret_store: Arc<dyn SecretStore>) -> Self {
        Self { secret_store }
    }
}

#[async_trait]
impl MatrixHttpCredentialMaterialProvider for MatrixSecretStoreCredentialMaterialProvider {
    async fn resolve_matrix_credential_material(
        &self,
        scope: &ResourceScope,
        endpoint: &MatrixHttpDeliveryEndpoint,
    ) -> Result<HostRuntimeCredentialMaterial, DeliveryError> {
        let lease = self
            .secret_store
            .lease_once(scope, endpoint.credential_secret())
            .await
            .map_err(matrix_credential_store_error)?;
        let material = self
            .secret_store
            .consume(scope, lease.id)
            .await
            .map_err(matrix_credential_store_error)?;
        Ok(HostRuntimeCredentialMaterial {
            handle: endpoint.credential_secret().clone(),
            material,
            target: RuntimeCredentialTarget::Header {
                name: "authorization".to_string(),
                prefix: Some("Bearer ".to_string()),
            },
            required: true,
        })
    }
}

fn matrix_credential_store_error(error: SecretStoreError) -> DeliveryError {
    let reason = match error {
        SecretStoreError::BackendMisconfigured { .. }
        | SecretStoreError::StoreUnavailable { .. } => DeliveryReasonCode::MatrixServerError,
        SecretStoreError::UnknownSecret { .. }
        | SecretStoreError::UnknownLease { .. }
        | SecretStoreError::LeaseConsumed { .. }
        | SecretStoreError::LeaseRevoked { .. }
        | SecretStoreError::LeaseExpired { .. }
        | SecretStoreError::SecretExpired => DeliveryReasonCode::UnauthorizedTarget,
    };
    DeliveryError::new(reason)
}

pub trait MatrixHttpDeliveryEndpointResolver: Send + Sync {
    fn resolve_endpoint(
        &self,
        route: &ValidatedDeliveryRoute,
        credential: &ResolvedCredentialHandle,
    ) -> Option<MatrixHttpDeliveryEndpoint>;
}

pub struct MatrixHttpDeliveryPort {
    egress: Arc<dyn MatrixHostHttpEgress>,
    endpoint_resolver: Arc<dyn MatrixHttpDeliveryEndpointResolver>,
    credential_material_provider: Arc<dyn MatrixHttpCredentialMaterialProvider>,
}

impl MatrixHttpDeliveryPort {
    pub fn new(
        egress: Arc<dyn MatrixHostHttpEgress>,
        endpoint_resolver: Arc<dyn MatrixHttpDeliveryEndpointResolver>,
        credential_material_provider: Arc<dyn MatrixHttpCredentialMaterialProvider>,
    ) -> Self {
        Self {
            egress,
            endpoint_resolver,
            credential_material_provider,
        }
    }
}

#[async_trait]
pub trait MatrixHostHttpEgress: Send + Sync {
    async fn execute_matrix_http(
        &self,
        request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError>;
}

#[async_trait]
impl MatrixHostHttpEgress for HostRuntimeHttpEgressPort {
    async fn execute_matrix_http(
        &self,
        request: HostRuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        self.execute(request).await
    }
}

#[async_trait]
impl MatrixDeliveryPort for MatrixHttpDeliveryPort {
    async fn deliver(
        &self,
        command: ProtocolDeliveryIntent,
        route: ValidatedDeliveryRoute,
        credential: ResolvedCredentialHandle,
        attempt: DeliveryAttemptContext,
    ) -> DeliveryPortResult {
        let ProtocolDeliveryIntent::Matrix(command) = command;
        let metadata = route.matrix_metadata().clone();
        let Some(endpoint) = self.endpoint_resolver.resolve_endpoint(&route, &credential) else {
            return DeliveryPortResult::Rejected(DeliveryError::new(
                DeliveryReasonCode::MissingMatrixRoute,
            ));
        };
        if endpoint.credential_handle_fingerprint != credential.credential_handle_fingerprint
            || endpoint.credential_handle_fingerprint != metadata.credential_handle_fingerprint
            || redacted_sha256_fingerprint(endpoint.homeserver_origin.as_bytes())
                != metadata.homeserver_origin_fingerprint
        {
            return DeliveryPortResult::Rejected(DeliveryError::new(
                DeliveryReasonCode::UnauthorizedTarget,
            ));
        }

        let request = matrix_send_request(&route, &command, &endpoint);
        let resource_scope = route.scope().to_resource_scope();
        let credential_material = match self
            .credential_material_provider
            .resolve_matrix_credential_material(&resource_scope, &endpoint)
            .await
        {
            Ok(credential) => credential,
            Err(error) => return DeliveryPortResult::Rejected(error),
        };
        let host_request = match matrix_host_http_request(request, credential_material) {
            Ok(request) => request,
            Err(error) => return DeliveryPortResult::Rejected(error),
        };
        observability::record_send_attempt_started(&attempt, command.command_kind, &metadata);
        let started_at = Utc::now();
        match self.egress.execute_matrix_http(host_request).await {
            Ok(response) => classify_matrix_http_response(
                response, &command, &metadata, &endpoint, &attempt, started_at,
            ),
            Err(error) => DeliveryPortResult::Rejected(matrix_delivery_error_from_egress(error)),
        }
    }
}

fn matrix_send_request(
    route: &ValidatedDeliveryRoute,
    command: &MatrixOutboundCommand,
    endpoint: &MatrixHttpDeliveryEndpoint,
) -> RuntimeHttpEgressRequest {
    let room = encode_matrix_path_segment(command.room_id.as_str());
    let txn = encode_matrix_path_segment(command.transaction_id.as_str());
    let path = format!("{MATRIX_SEND_PATH_PREFIX}{room}{MATRIX_SEND_EVENT_PATH}{txn}");
    RuntimeHttpEgressRequest {
        runtime: RuntimeKind::FirstParty,
        scope: route.route.scope().to_resource_scope(),
        capability_id: endpoint.capability_id.clone(),
        method: NetworkMethod::Put,
        url: format!("{}{}", endpoint.homeserver_origin, path),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: serde_json::to_vec(command.body.as_json()).unwrap_or_else(|_| b"{}".to_vec()),
        network_policy: NetworkPolicy {
            allowed_targets: vec![NetworkTargetPattern {
                scheme: Some(endpoint.scheme),
                host_pattern: endpoint.host.clone(),
                port: endpoint.port,
            }],
            deny_private_ip_ranges: true,
            max_egress_bytes: Some(endpoint.response_body_limit),
        },
        credential_injections: Vec::new(),
        response_body_limit: Some(endpoint.response_body_limit),
        save_body_to: None,
        timeout_ms: endpoint.timeout_ms,
    }
}

fn matrix_host_http_request(
    request: RuntimeHttpEgressRequest,
    credential_material: HostRuntimeCredentialMaterial,
) -> Result<HostRuntimeHttpEgressRequest, DeliveryError> {
    Ok(HostRuntimeHttpEgressRequest {
        extension_id: matrix_extension_id()?,
        trust: TrustClass::System,
        request,
        credentials: vec![credential_material],
    })
}

fn matrix_extension_id() -> Result<ExtensionId, DeliveryError> {
    ExtensionId::new("ironclaw_matrix")
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::MatrixBadRequest))
}

fn classify_matrix_http_response(
    response: RuntimeHttpEgressResponse,
    command: &MatrixOutboundCommand,
    metadata: &MatrixRouteMetadata,
    endpoint: &MatrixHttpDeliveryEndpoint,
    attempt: &DeliveryAttemptContext,
    started_at: DateTime<Utc>,
) -> DeliveryPortResult {
    let status_family = http_status_family(response.status);
    let body = serde_json::from_slice::<Value>(&response.body).ok();
    if (200..300).contains(&response.status) {
        let Some(event_id) = body
            .as_ref()
            .and_then(|body| body.get("event_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        else {
            observability::record_http_response_classified(
                attempt,
                metadata,
                response.status,
                status_family,
                None,
                Some(DeliveryReasonCode::MatrixMalformedResponse),
                elapsed_ms_since(started_at),
            );
            return DeliveryPortResult::Rejected(
                DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse)
                    .with_status_family(status_family),
            );
        };
        let latency_ms = elapsed_ms_since(started_at);
        observability::record_http_response_classified(
            attempt,
            metadata,
            response.status,
            status_family,
            None,
            None,
            latency_ms,
        );
        return DeliveryPortResult::Accepted(ProtocolDeliveryEvidence::Matrix(
            MatrixDeliveryEvidenceV1 {
                schema_version: 1,
                delivery_id: attempt.delivery_id,
                attempt_number: attempt.attempt_number,
                event_id_fingerprint: redacted_sha256_fingerprint(event_id.as_bytes()),
                transaction_id: command.transaction_id.clone(),
                command_kind: command.command_kind,
                delivered_at: Utc::now(),
                verified: true,
                homeserver_origin_fingerprint: metadata.homeserver_origin_fingerprint.clone(),
                room_fingerprint: metadata.room_fingerprint.clone(),
                installation_scoped_credential_ref: endpoint.credential_handle_fingerprint.clone(),
                http_status: response.status,
                latency_ms,
            },
        ));
    }

    let matrix_errcode = body
        .as_ref()
        .and_then(|body| body.get("errcode"))
        .and_then(Value::as_str)
        .map(MatrixErrcode::from_matrix_errcode);
    let mut error = DeliveryError::new(reason_for_matrix_http_status(
        response.status,
        matrix_errcode,
    ))
    .with_status_family(status_family);
    if let Some(errcode) = matrix_errcode {
        error = error.with_matrix_errcode(errcode);
    }
    if matches!(error.reason, DeliveryReasonCode::MatrixRateLimited)
        && let Some(after) = matrix_retry_after(&response, body.as_ref())
    {
        error = error.with_retry_hint(after);
    }
    observability::record_http_response_classified(
        attempt,
        metadata,
        response.status,
        status_family,
        matrix_errcode,
        Some(error.reason),
        elapsed_ms_since(started_at),
    );
    DeliveryPortResult::Rejected(error)
}

fn elapsed_ms_since(started_at: DateTime<Utc>) -> u64 {
    Utc::now()
        .signed_duration_since(started_at)
        .num_milliseconds()
        .max(0) as u64
}

pub(crate) fn reason_for_matrix_http_status(
    status: u16,
    matrix_errcode: Option<MatrixErrcode>,
) -> DeliveryReasonCode {
    match (status, matrix_errcode) {
        (429, _) | (_, Some(MatrixErrcode::LimitExceeded)) => DeliveryReasonCode::MatrixRateLimited,
        (401 | 403, _)
        | (
            _,
            Some(
                MatrixErrcode::Forbidden
                | MatrixErrcode::UnknownToken
                | MatrixErrcode::UserDeactivated,
            ),
        ) => DeliveryReasonCode::UnauthorizedTarget,
        (_, Some(MatrixErrcode::TooLarge)) => DeliveryReasonCode::MatrixMessageTooLarge,
        (_, Some(MatrixErrcode::UnsupportedRoomVersion)) => {
            DeliveryReasonCode::MatrixUnsupportedRoomVersion
        }
        (_, Some(MatrixErrcode::NotFound)) => DeliveryReasonCode::MatrixNotFound,
        (_, Some(MatrixErrcode::BadJson)) => DeliveryReasonCode::MatrixBadRequest,
        (500..=599, _) => DeliveryReasonCode::MatrixServerError,
        (300..=399, _) => DeliveryReasonCode::UnauthorizedTarget,
        (400..=499, _) => DeliveryReasonCode::MatrixBadRequest,
        _ => DeliveryReasonCode::MatrixMalformedResponse,
    }
}

fn matrix_delivery_error_from_egress(error: RuntimeHttpEgressError) -> DeliveryError {
    match error.reason_code() {
        ironclaw_host_api::RuntimeHttpEgressReasonCode::CredentialUnavailable
        | ironclaw_host_api::RuntimeHttpEgressReasonCode::RequestDenied
        | ironclaw_host_api::RuntimeHttpEgressReasonCode::PolicyDenied => {
            DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::NetworkError => {
            DeliveryError::new(DeliveryReasonCode::MatrixTimeout)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::ResponseError => {
            DeliveryError::new(DeliveryReasonCode::MatrixServerError)
        }
        ironclaw_host_api::RuntimeHttpEgressReasonCode::ResponseBodyLimitExceeded => {
            DeliveryError::new(DeliveryReasonCode::MatrixMalformedResponse)
        }
    }
}

fn matrix_retry_after(
    response: &RuntimeHttpEgressResponse,
    body: Option<&Value>,
) -> Option<Duration> {
    body.and_then(|body| body.get("retry_after_ms"))
        .and_then(Value::as_u64)
        .map(Duration::from_millis)
        .or_else(|| {
            response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, value)| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
        })
}

fn http_status_family(status: u16) -> Option<HttpStatusFamily> {
    Some(match status {
        100..=199 => HttpStatusFamily::Informational,
        200..=299 => HttpStatusFamily::Success,
        300..=399 => HttpStatusFamily::Redirect,
        400..=499 => HttpStatusFamily::ClientError,
        500..=599 => HttpStatusFamily::ServerError,
        _ => return None,
    })
}

fn parse_matrix_homeserver_origin(
    origin: &str,
) -> Result<(NetworkScheme, String, Option<u16>), DeliveryError> {
    let parsed = Url::parse(origin)
        .map_err(|_| DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget))?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.cannot_be_a_base()
        || parsed.path() != "/"
    {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    }
    let scheme = match parsed.scheme() {
        "https" => NetworkScheme::Https,
        _ => return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget)),
    };
    let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    };
    if host_is_disallowed_matrix_origin(&host) {
        return Err(DeliveryError::new(DeliveryReasonCode::UnauthorizedTarget));
    }
    Ok((scheme, host, parsed.port()))
}

fn host_is_disallowed_matrix_origin(host: &str) -> bool {
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return disallowed_matrix_ip(ip);
    }
    host.chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

fn disallowed_matrix_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn canonical_matrix_homeserver_origin(
    scheme: NetworkScheme,
    host: &str,
    port: Option<u16>,
) -> String {
    let scheme = match scheme {
        NetworkScheme::Http => "http",
        NetworkScheme::Https => "https",
    };
    match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

fn redacted_sha256_fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

pub(crate) fn encode_matrix_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
