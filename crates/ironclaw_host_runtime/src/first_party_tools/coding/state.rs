use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::sync::RwLock;

use crate::{FirstPartyCapabilityError, FirstPartyCapabilityRequest};

use super::guest_error;

pub(crate) type SharedCodingReadState = Arc<RwLock<CodingReadState>>;

#[derive(Debug, Default)]
pub(crate) struct CodingReadState {
    entries: HashMap<(CodingReadScopeKey, String), CodingReadEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CodingReadScopeKey {
    tenant_id: String,
    user_id: String,
    agent_id: Option<String>,
    project_id: Option<String>,
    mission_id: Option<String>,
    thread_id: Option<String>,
}

#[derive(Debug, Clone)]
struct CodingReadEntry {
    modified: Option<SystemTime>,
    partial: bool,
}

impl CodingReadState {
    pub(super) fn record_read(
        &mut self,
        scope: CodingReadScopeKey,
        path: String,
        modified: Option<SystemTime>,
        partial: bool,
    ) {
        self.entries
            .insert((scope, path), CodingReadEntry { modified, partial });
    }

    pub(super) fn check_before_edit(
        &self,
        scope: &CodingReadScopeKey,
        path: &str,
        current_modified: Option<SystemTime>,
    ) -> Result<(), FirstPartyCapabilityError> {
        let key = (scope.clone(), path.to_string());
        let Some(entry) = self.entries.get(&key) else {
            return Err(guest_error());
        };
        if entry.partial {
            return Err(guest_error());
        }
        if let (Some(current), Some(previous)) = (current_modified, entry.modified)
            && let Ok(delta) = current.duration_since(previous)
            && delta > Duration::from_secs(1)
        {
            return Err(guest_error());
        }
        Ok(())
    }

    pub(super) fn update_mtime(
        &mut self,
        scope: &CodingReadScopeKey,
        path: &str,
        modified: Option<SystemTime>,
    ) {
        let key = (scope.clone(), path.to_string());
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.modified = modified;
            entry.partial = false;
        }
    }
}

pub(super) fn read_scope_key(request: &FirstPartyCapabilityRequest) -> CodingReadScopeKey {
    CodingReadScopeKey {
        tenant_id: request.scope.tenant_id.as_str().to_string(),
        user_id: request.scope.user_id.as_str().to_string(),
        agent_id: request
            .scope
            .agent_id
            .as_ref()
            .map(|value| value.as_str().to_string()),
        project_id: request
            .scope
            .project_id
            .as_ref()
            .map(|value| value.as_str().to_string()),
        mission_id: request
            .scope
            .mission_id
            .as_ref()
            .map(|value| value.as_str().to_string()),
        thread_id: request
            .scope
            .thread_id
            .as_ref()
            .map(|value| value.as_str().to_string()),
    }
}
