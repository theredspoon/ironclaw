//! Declared-host + credential-handle egress policy enforcement.
//!
//! `EgressPolicy` is the per-installation allow-list. When the host wires a
//! [`ironclaw_product_adapters::ProtocolHttpEgress`] for a v2 adapter, it
//! consults this policy on every request:
//!
//! 1. The target host must be in the adapter's declared host list.
//! 2. The credential handle (if any) must be one the policy was told this
//!    adapter installation may consume.
//!
//! The host applies the resolved credential at request time; the credential
//! material is never reachable from this struct.

use std::collections::BTreeSet;

use ironclaw_product_adapters::{DeclaredEgressHost, EgressCredentialHandle};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EgressPolicyError {
    #[error("egress to undeclared host {host}")]
    UndeclaredHost { host: DeclaredEgressHost },
    #[error("egress credential handle {handle} is unauthorized for this adapter installation")]
    UnauthorizedCredentialHandle { handle: EgressCredentialHandle },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicyTarget<'a> {
    pub host: &'a DeclaredEgressHost,
    pub credential_handle: Option<&'a EgressCredentialHandle>,
}

#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    declared_hosts: BTreeSet<DeclaredEgressHost>,
    allowed_credential_handles: BTreeSet<EgressCredentialHandle>,
}

impl EgressPolicy {
    pub fn new(
        declared_hosts: impl IntoIterator<Item = DeclaredEgressHost>,
        allowed_credential_handles: impl IntoIterator<Item = EgressCredentialHandle>,
    ) -> Self {
        Self {
            declared_hosts: declared_hosts.into_iter().collect(),
            allowed_credential_handles: allowed_credential_handles.into_iter().collect(),
        }
    }

    pub fn check(&self, target: EgressPolicyTarget<'_>) -> Result<(), EgressPolicyError> {
        if !self.declared_hosts.contains(target.host) {
            return Err(EgressPolicyError::UndeclaredHost {
                host: target.host.clone(),
            });
        }
        if let Some(handle) = target.credential_handle
            && !self.allowed_credential_handles.contains(handle)
        {
            return Err(EgressPolicyError::UnauthorizedCredentialHandle {
                handle: handle.clone(),
            });
        }
        Ok(())
    }

    pub fn declared_hosts(&self) -> impl Iterator<Item = &DeclaredEgressHost> {
        self.declared_hosts.iter()
    }

    pub fn allowed_credential_handles(&self) -> impl Iterator<Item = &EgressCredentialHandle> {
        self.allowed_credential_handles.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> DeclaredEgressHost {
        DeclaredEgressHost::new(value).expect("valid")
    }

    fn handle(value: &str) -> EgressCredentialHandle {
        EgressCredentialHandle::new(value).expect("valid")
    }

    #[test]
    fn declared_host_with_known_handle_passes() {
        let policy = EgressPolicy::new([host("api.telegram.org")], [handle("telegram_bot_token")]);
        let target_host = host("api.telegram.org");
        let target_handle = handle("telegram_bot_token");
        assert!(
            policy
                .check(EgressPolicyTarget {
                    host: &target_host,
                    credential_handle: Some(&target_handle),
                })
                .is_ok()
        );
    }

    #[test]
    fn undeclared_host_fails_closed() {
        let policy = EgressPolicy::new([host("api.telegram.org")], [handle("telegram_bot_token")]);
        let other = host("evil.example.com");
        let err = policy
            .check(EgressPolicyTarget {
                host: &other,
                credential_handle: None,
            })
            .expect_err("undeclared");
        assert!(matches!(err, EgressPolicyError::UndeclaredHost { .. }));
    }

    #[test]
    fn unknown_handle_fails_closed_even_for_declared_host() {
        let policy = EgressPolicy::new([host("api.telegram.org")], [handle("telegram_bot_token")]);
        let target_host = host("api.telegram.org");
        let target_handle = handle("ghost_token");
        let err = policy
            .check(EgressPolicyTarget {
                host: &target_host,
                credential_handle: Some(&target_handle),
            })
            .expect_err("unauthorized handle");
        assert!(matches!(
            err,
            EgressPolicyError::UnauthorizedCredentialHandle { .. }
        ));
    }

    #[test]
    fn multiple_declared_hosts_and_handles_preserve_typed_policy_membership() {
        let policy = EgressPolicy::new(
            [host("api.slack.com"), host("api.telegram.org")],
            [handle("slack_bot_token"), handle("telegram_bot_token")],
        );

        let declared_hosts = policy
            .declared_hosts()
            .map(DeclaredEgressHost::as_str)
            .collect::<Vec<_>>();
        assert_eq!(declared_hosts, ["api.slack.com", "api.telegram.org"]);

        let allowed_handles = policy
            .allowed_credential_handles()
            .map(EgressCredentialHandle::as_str)
            .collect::<Vec<_>>();
        assert_eq!(allowed_handles, ["slack_bot_token", "telegram_bot_token"]);

        let slack_host = host("api.slack.com");
        let telegram_host = host("api.telegram.org");
        let slack_handle = handle("slack_bot_token");
        let telegram_handle = handle("telegram_bot_token");
        assert!(
            policy
                .check(EgressPolicyTarget {
                    host: &slack_host,
                    credential_handle: Some(&slack_handle),
                })
                .is_ok()
        );
        assert!(
            policy
                .check(EgressPolicyTarget {
                    host: &telegram_host,
                    credential_handle: Some(&telegram_handle),
                })
                .is_ok()
        );

        let evil_host = host("evil.example.com");
        let undeclared_err = policy
            .check(EgressPolicyTarget {
                host: &evil_host,
                credential_handle: Some(&slack_handle),
            })
            .expect_err("undeclared host");
        assert_eq!(
            undeclared_err,
            EgressPolicyError::UndeclaredHost { host: evil_host }
        );

        let ghost_handle = handle("ghost_token");
        let unauthorized_err = policy
            .check(EgressPolicyTarget {
                host: &slack_host,
                credential_handle: Some(&ghost_handle),
            })
            .expect_err("unauthorized handle");
        assert_eq!(
            unauthorized_err,
            EgressPolicyError::UnauthorizedCredentialHandle {
                handle: ghost_handle,
            }
        );
    }
}
