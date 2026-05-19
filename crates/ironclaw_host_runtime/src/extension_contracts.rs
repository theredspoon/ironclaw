use std::sync::Arc;

use ironclaw_extensions::{
    CapabilityProviderHostApiContract, ExtensionDiscovery, ExtensionError, ExtensionRegistry,
    HostApiContractRegistry, ManifestV2Error,
};
use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{HostPortCatalog, VirtualPath};
use ironclaw_product_adapter_registry::ProductAdapterHostApiContract;

/// Build the host-runtime default set of Extension Manifest v2 host API contracts.
///
/// This is composition-only: contracts validate and project manifest declarations,
/// but do not execute runtime code, resolve schema files, or publish hot surfaces.
pub fn default_host_api_contract_registry() -> Result<HostApiContractRegistry, ManifestV2Error> {
    let mut registry = HostApiContractRegistry::new();
    registry.register(Arc::new(CapabilityProviderHostApiContract::new()?))?;
    let product_adapter_contract =
        ProductAdapterHostApiContract::new().map_err(|error| ManifestV2Error::Invalid {
            reason: format!("product adapter host API contract registration failed: {error}"),
        })?;
    registry.register(Arc::new(product_adapter_contract))?;
    Ok(registry)
}

/// Discover installed extensions through host-runtime's default host API contracts.
///
/// Callers still own the supported [`HostPortCatalog`]; PR3 intentionally keeps
/// that catalog empty unless composition supplies real host ports in a later slice.
pub async fn discover_extensions_with_default_host_api_contracts<F>(
    fs: &F,
    root: &VirtualPath,
    host_port_catalog: &HostPortCatalog,
) -> Result<ExtensionRegistry, ExtensionError>
where
    F: RootFilesystem,
{
    let contracts = default_host_api_contract_registry()?;
    ExtensionDiscovery::discover_with_manifest_contracts(
        fs,
        root,
        ironclaw_extensions::ManifestSource::InstalledLocal,
        host_port_catalog,
        &contracts,
    )
    .await
}
