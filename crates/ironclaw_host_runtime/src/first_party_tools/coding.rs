use std::{
    cmp::Reverse,
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use glob::{MatchOptions, Pattern};
use ironclaw_extensions::{CapabilityManifest, ExtensionError};
use ironclaw_filesystem::{DirEntry, FileStat, FileType, FilesystemError, FilesystemOperation};
use ironclaw_host_api::{
    CapabilityId, EffectKind, MountGrant, PermissionMode, RuntimeDispatchErrorKind, ScopedPath,
    VirtualPath,
};
use ironclaw_safety::sensitive_paths::is_sensitive_path;
use regex::RegexBuilder;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::{FirstPartyCapabilityError, FirstPartyCapabilityRequest};

use super::{guest_error, input_error, resource_profile};

pub const READ_FILE_CAPABILITY_ID: &str = "builtin.read_file";
pub const WRITE_FILE_CAPABILITY_ID: &str = "builtin.write_file";
pub const LIST_DIR_CAPABILITY_ID: &str = "builtin.list_dir";
pub const GLOB_CAPABILITY_ID: &str = "builtin.glob";
pub const GREP_CAPABILITY_ID: &str = "builtin.grep";
pub const APPLY_PATCH_CAPABILITY_ID: &str = "builtin.apply_patch";

pub(super) type SharedCodingReadState = Arc<RwLock<CodingReadState>>;

const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;
const DEFAULT_LINE_LIMIT: usize = 2_000;
const MAX_WRITE_SIZE: usize = 5 * 1024 * 1024;
const MAX_PATCH_SIZE: u64 = 10 * 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 500;
const DEFAULT_MAX_RESULTS: usize = 200;
const MAX_OUTPUT_SIZE: usize = 64 * 1024;
const DEFAULT_HEAD_LIMIT: usize = 250;
const MAX_VISITED_ENTRIES: usize = 50_000;
const DEFAULT_SCOPED_ROOT: &str = "/workspace";
const WORKSPACE_FILES: &[&str] = &[
    "HEARTBEAT.md",
    "MEMORY.md",
    "IDENTITY.md",
    "SOUL.md",
    "AGENTS.md",
    "USER.md",
    "README.md",
];
const GLOB_MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".turbo",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
];

pub(super) fn manifests() -> Result<Vec<CapabilityManifest>, ExtensionError> {
    Ok(vec![
        manifest(
            READ_FILE_CAPABILITY_ID,
            "Read a file through scoped mounts with v1 read_file output shape",
            vec![EffectKind::ReadFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" }
                },
                "required": ["path"]
            }),
        )?,
        manifest(
            WRITE_FILE_CAPABILITY_ID,
            "Write content through scoped mounts with v1 write_file output shape",
            vec![EffectKind::WriteFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }),
        )?,
        manifest(
            LIST_DIR_CAPABILITY_ID,
            "List directory contents through scoped mounts with v1 list_dir output shape",
            vec![EffectKind::ReadFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "recursive": { "type": "boolean" },
                    "max_depth": { "type": "integer" }
                }
            }),
        )?,
        manifest(
            GLOB_CAPABILITY_ID,
            "Find files under a scoped directory with v1 glob output shape",
            vec![EffectKind::ReadFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "path": { "type": "string" },
                    "max_results": { "type": "integer" }
                },
                "required": ["pattern"]
            }),
        )?,
        manifest(
            GREP_CAPABILITY_ID,
            "Search scoped file contents with v1 grep output modes",
            vec![EffectKind::ReadFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "path": { "type": "string" },
                    "glob": { "type": "string" },
                    "output_mode": { "type": "string", "enum": ["content", "files_with_matches", "count"] },
                    "context": { "type": "integer" },
                    "before_context": { "type": "integer" },
                    "after_context": { "type": "integer" },
                    "case_insensitive": { "type": "boolean" },
                    "head_limit": { "type": "integer" },
                    "offset": { "type": "integer" },
                    "multiline": { "type": "boolean" },
                    "type_filter": { "type": "string" }
                },
                "required": ["pattern"]
            }),
        )?,
        manifest(
            APPLY_PATCH_CAPABILITY_ID,
            "Apply exact/fuzzy search-replace edits through scoped mounts",
            vec![EffectKind::ReadFilesystem, EffectKind::WriteFilesystem],
            PermissionMode::Allow,
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "old_string": { "type": "string" },
                    "new_string": { "type": "string" },
                    "replace_all": { "type": "boolean" }
                },
                "required": ["path", "old_string", "new_string"]
            }),
        )?,
    ])
}

fn manifest(
    id: &str,
    description: &str,
    effects: Vec<EffectKind>,
    default_permission: PermissionMode,
    parameters_schema: Value,
) -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(id)?,
        description: description.to_string(),
        effects,
        default_permission,
        parameters_schema,
        resource_profile: resource_profile(),
    })
}

pub(super) async fn dispatch(
    request: &FirstPartyCapabilityRequest,
    read_state: &SharedCodingReadState,
) -> Result<Value, FirstPartyCapabilityError> {
    match request.capability_id.as_str() {
        READ_FILE_CAPABILITY_ID => read_file(request, read_state).await,
        WRITE_FILE_CAPABILITY_ID => write_file(request, read_state).await,
        LIST_DIR_CAPABILITY_ID => list_dir(request).await,
        GLOB_CAPABILITY_ID => glob(request).await,
        GREP_CAPABILITY_ID => grep(request).await,
        APPLY_PATCH_CAPABILITY_ID => apply_patch(request, read_state).await,
        _ => Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::UndeclaredCapability,
        )),
    }
}

async fn read_file(
    request: &FirstPartyCapabilityRequest,
    read_state: &SharedCodingReadState,
) -> Result<Value, FirstPartyCapabilityError> {
    let resolved = resolve_required_path(request, "path", FilesystemOperation::ReadFile)?;
    let offset = optional_usize(&request.input, "offset")?.unwrap_or(0);
    let limit = optional_usize(&request.input, "limit")?;
    let has_explicit_range = offset > 0 || limit.is_some();
    let stat = request
        .filesystem
        .stat(&resolved.virtual_path)
        .await
        .map_err(filesystem_error)?;
    if stat.sensitive {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    if stat.file_type != FileType::File || stat.len > MAX_READ_SIZE {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::Resource,
        ));
    }

    let bytes = request
        .filesystem
        .read_file(&resolved.virtual_path)
        .await
        .map_err(filesystem_error)?;
    reject_binary_probe(&bytes)?;
    let (content, _encoding, _line_ending) = decode_text(&bytes)?;
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    let start_line = offset.saturating_sub(1);
    let start_line = start_line.min(total_lines);
    let (end_line, truncated_by_default) = if let Some(limit) = limit {
        ((start_line + limit).min(total_lines), false)
    } else if !has_explicit_range && total_lines > DEFAULT_LINE_LIMIT {
        (DEFAULT_LINE_LIMIT.min(total_lines), true)
    } else {
        (total_lines, false)
    };
    let selected_lines: Vec<String> = lines[start_line..end_line]
        .iter()
        .enumerate()
        .map(|(index, line)| format!("{:>6}│ {}", start_line + index + 1, line))
        .collect();

    let partial = has_explicit_range || truncated_by_default;
    read_state.write().await.record_read(
        read_scope_key(request),
        resolved.virtual_path.as_str().to_string(),
        stat.modified,
        partial,
    );

    Ok(json!({
        "content": selected_lines.join("\n"),
        "total_lines": total_lines,
        "lines_shown": end_line - start_line,
        "truncated_by_default": truncated_by_default,
        "path": resolved.scoped_path.as_str()
    }))
}

async fn write_file(
    request: &FirstPartyCapabilityRequest,
    read_state: &SharedCodingReadState,
) -> Result<Value, FirstPartyCapabilityError> {
    let path_str = required_str(&request.input, "path")?;
    if is_workspace_path(path_str) {
        return Err(input_error());
    }
    let resolved = resolve_required_path(request, "path", FilesystemOperation::WriteFile)?;
    if let Some(stat) = stat_optional(request, &resolved.virtual_path).await?
        && stat.sensitive
    {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    let content = required_str(&request.input, "content")?;
    if content.len() > MAX_WRITE_SIZE {
        return Err(input_error());
    }
    create_parent_dir(request, &resolved.virtual_path).await?;
    request
        .filesystem
        .write_file(&resolved.virtual_path, content.as_bytes())
        .await
        .map_err(filesystem_error)?;
    if let Some(stat) = stat_optional(request, &resolved.virtual_path).await? {
        read_state.write().await.update_mtime(
            &read_scope_key(request),
            resolved.virtual_path.as_str(),
            stat.modified,
        );
    }
    Ok(json!({
        "path": resolved.scoped_path.as_str(),
        "bytes_written": content.len(),
        "success": true
    }))
}

async fn list_dir(
    request: &FirstPartyCapabilityRequest,
) -> Result<Value, FirstPartyCapabilityError> {
    let start = std::time::Instant::now();
    let resolved = resolve_optional_path(request, FilesystemOperation::ListDir)?;
    let recursive = request
        .input
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_depth = optional_usize(&request.input, "max_depth")?.unwrap_or(3);
    let mut entries = collect_list_entries(request, &resolved, recursive, max_depth).await?;
    sort_list_entries(&mut entries);
    let truncated = entries.len() > MAX_DIR_ENTRIES;
    entries.truncate(MAX_DIR_ENTRIES);
    let count = entries.len();
    let _duration = start.elapsed();
    Ok(json!({
        "path": resolved.scoped_path.as_str(),
        "entries": entries.into_iter().map(|entry| entry.display).collect::<Vec<_>>(),
        "count": count,
        "truncated": truncated
    }))
}

async fn glob(request: &FirstPartyCapabilityRequest) -> Result<Value, FirstPartyCapabilityError> {
    let start = std::time::Instant::now();
    let pattern = required_str(&request.input, "pattern")?;
    validate_relative_pattern(pattern)?;
    let resolved = resolve_optional_path(request, FilesystemOperation::ListDir)?;
    let max_results = optional_usize(&request.input, "max_results")?.unwrap_or(DEFAULT_MAX_RESULTS);
    let pattern = Pattern::new(pattern).map_err(|_| input_error())?;
    let mut files = Vec::new();
    walk_entries(request, &resolved, |entry, relative| {
        let scoped_path = scoped_child_path(&resolved.scoped_path, relative);
        if entry.file_type == FileType::File
            && !is_excluded_relative_path(relative)
            && !is_sensitive_scoped_path(&scoped_path)
            && pattern.matches_with(relative, GLOB_MATCH_OPTIONS)
        {
            files.push((relative.to_string(), entry.path.clone()));
        }
        Ok(true)
    })
    .await?;
    let mut files_with_mtime = Vec::with_capacity(files.len());
    for (relative, path) in files {
        let stat = request
            .filesystem
            .stat(&path)
            .await
            .map_err(filesystem_error)?;
        if stat.sensitive {
            continue;
        }
        let modified = stat.modified.unwrap_or(UNIX_EPOCH);
        files_with_mtime.push((relative, modified));
    }
    files_with_mtime.sort_by_key(|entry| Reverse(entry.1));
    let truncated = files_with_mtime.len() > max_results;
    files_with_mtime.truncate(max_results);
    let files = files_with_mtime
        .into_iter()
        .map(|(relative, _)| relative)
        .collect::<Vec<_>>();
    let count = files.len();
    Ok(json!({
        "files": files,
        "count": count,
        "truncated": truncated,
        "duration_ms": start.elapsed().as_millis() as u64
    }))
}

async fn grep(request: &FirstPartyCapabilityRequest) -> Result<Value, FirstPartyCapabilityError> {
    let resolved = resolve_optional_path(request, FilesystemOperation::Stat)?;
    if !operation_allowed(&resolved.grant.permissions, FilesystemOperation::ReadFile) {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    let root_stat = request
        .filesystem
        .stat(&resolved.virtual_path)
        .await
        .map_err(filesystem_error)?;
    if root_stat.sensitive {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    if root_stat.file_type == FileType::Directory
        && !operation_allowed(&resolved.grant.permissions, FilesystemOperation::ListDir)
    {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    if !matches!(root_stat.file_type, FileType::File | FileType::Directory) {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::Resource,
        ));
    }
    let pattern = required_str(&request.input, "pattern")?;
    let output_mode = request
        .input
        .get("output_mode")
        .and_then(Value::as_str)
        .unwrap_or("files_with_matches");
    if !matches!(output_mode, "content" | "files_with_matches" | "count") {
        return Err(input_error());
    }
    let glob_filter = request.input.get("glob").and_then(Value::as_str);
    if let Some(filter) = glob_filter {
        validate_relative_pattern(filter)?;
    }
    let glob_filter = glob_filter
        .map(Pattern::new)
        .transpose()
        .map_err(|_| input_error())?;
    let type_filter = request.input.get("type_filter").and_then(Value::as_str);
    let case_insensitive = request
        .input
        .get("case_insensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let multiline = request
        .input
        .get("multiline")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .multi_line(true)
        .dot_matches_new_line(multiline)
        .build()
        .map_err(|_| input_error())?;
    let context = optional_usize(&request.input, "context")?;
    let before_context = if let Some(context) = context {
        context
    } else {
        optional_usize(&request.input, "before_context")?.unwrap_or(0)
    };
    let after_context = if let Some(context) = context {
        context
    } else {
        optional_usize(&request.input, "after_context")?.unwrap_or(0)
    };
    let head_limit = optional_usize_allow_zero(&request.input, "head_limit")?;
    let offset = optional_usize(&request.input, "offset")?.unwrap_or(0);
    let mut search_results = Vec::new();

    walk_files(
        request,
        &resolved,
        root_stat,
        |relative| {
            if let Some(filter) = &glob_filter
                && !filter.matches(relative)
            {
                return false;
            }
            if let Some(type_filter) = type_filter
                && !type_filter_matches(relative, type_filter)
            {
                return false;
            }
            true
        },
        |relative, bytes, modified| {
            if reject_binary_probe(bytes).is_err() {
                return Ok(true);
            }
            let Ok((content, _encoding, _line_ending)) = decode_text(bytes) else {
                return Ok(true);
            };
            if regex.is_match(&content) {
                let line_matches = line_matches(&content, &regex, before_context, after_context);
                let count = line_matches.iter().filter(|line| line.is_match).count();
                search_results.push(GrepFileResult {
                    relative: relative.to_string(),
                    modified,
                    count,
                    lines: line_matches,
                });
            }
            Ok(true)
        },
    )
    .await?;

    if output_mode == "files_with_matches" {
        search_results.sort_by(|left, right| {
            Reverse(left.modified.unwrap_or(UNIX_EPOCH))
                .cmp(&Reverse(right.modified.unwrap_or(UNIX_EPOCH)))
                .then_with(|| left.relative.cmp(&right.relative))
        });
    } else {
        search_results.sort_by(|left, right| left.relative.cmp(&right.relative));
    }
    Ok(build_grep_output(
        output_mode,
        search_results,
        offset,
        head_limit,
        before_context > 0 || after_context > 0,
    ))
}

async fn apply_patch(
    request: &FirstPartyCapabilityRequest,
    read_state: &SharedCodingReadState,
) -> Result<Value, FirstPartyCapabilityError> {
    let path_str = required_str(&request.input, "path")?;
    if is_workspace_path(path_str) {
        return Err(input_error());
    }
    let resolved = resolve_required_path(request, "path", FilesystemOperation::ReadFile)?;
    if !operation_allowed(&resolved.grant.permissions, FilesystemOperation::WriteFile) {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    let old_string = required_str(&request.input, "old_string")?;
    let new_string = required_str(&request.input, "new_string")?;
    if old_string == new_string {
        return Err(input_error());
    }
    let replace_all = request
        .input
        .get("replace_all")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stat = request
        .filesystem
        .stat(&resolved.virtual_path)
        .await
        .map_err(filesystem_error)?;
    if stat.sensitive {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    read_state.read().await.check_before_edit(
        &read_scope_key(request),
        resolved.virtual_path.as_str(),
        stat.modified,
    )?;
    if stat.file_type != FileType::File || stat.len > MAX_PATCH_SIZE {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::Resource,
        ));
    }
    let bytes = request
        .filesystem
        .read_file(&resolved.virtual_path)
        .await
        .map_err(filesystem_error)?;
    reject_binary_probe(&bytes)?;
    let (content, encoding, line_ending) = decode_text(&bytes)?;
    let (match_count, match_method) = count_matches(&content, old_string);
    if match_count == 0 {
        return Err(guest_error());
    }
    if !replace_all && match_count > 1 {
        return Err(guest_error());
    }

    let (new_content, replacements) =
        replace_content(&content, old_string, new_string, replace_all, match_count)?;
    let output = encode_text(&new_content, encoding, line_ending);
    request
        .filesystem
        .write_file(&resolved.virtual_path, &output)
        .await
        .map_err(filesystem_error)?;
    if let Some(stat) = stat_optional(request, &resolved.virtual_path).await? {
        read_state.write().await.update_mtime(
            &read_scope_key(request),
            resolved.virtual_path.as_str(),
            stat.modified,
        );
    }
    let mut result = json!({
        "path": resolved.scoped_path.as_str(),
        "replacements": replacements,
        "success": true
    });
    if match_method != MatchMethod::Exact {
        result["match_method"] = json!(format!("{match_method:?}"));
    }
    Ok(result)
}

#[derive(Debug, Clone)]
struct ResolvedPath {
    scoped_path: ScopedPath,
    virtual_path: VirtualPath,
    grant: MountGrant,
}

#[derive(Debug)]
struct ListEntry {
    display: String,
    is_dir: bool,
}

#[derive(Debug)]
struct GrepFileResult {
    relative: String,
    modified: Option<SystemTime>,
    count: usize,
    lines: Vec<GrepLine>,
}

#[derive(Debug)]
struct GrepLine {
    number: usize,
    text: String,
    is_match: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileEncoding {
    Utf8,
    Utf16Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineEnding {
    Lf,
    CrLf,
    Cr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchMethod {
    Exact,
    TrailingWhitespace,
    QuoteNormalization,
    Both,
}

#[derive(Debug)]
struct FuzzyMatch {
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
pub(super) struct CodingReadState {
    entries: HashMap<(CodingReadScopeKey, String), CodingReadEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CodingReadScopeKey {
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
    fn record_read(
        &mut self,
        scope: CodingReadScopeKey,
        path: String,
        modified: Option<SystemTime>,
        partial: bool,
    ) {
        self.entries
            .insert((scope, path), CodingReadEntry { modified, partial });
    }

    fn check_before_edit(
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

    fn update_mtime(
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

fn read_scope_key(request: &FirstPartyCapabilityRequest) -> CodingReadScopeKey {
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

fn resolve_required_path(
    request: &FirstPartyCapabilityRequest,
    field: &str,
    operation: FilesystemOperation,
) -> Result<ResolvedPath, FirstPartyCapabilityError> {
    resolve_path(request, required_str(&request.input, field)?, operation)
}

fn resolve_optional_path(
    request: &FirstPartyCapabilityRequest,
    operation: FilesystemOperation,
) -> Result<ResolvedPath, FirstPartyCapabilityError> {
    let path = request
        .input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SCOPED_ROOT);
    resolve_path(request, path, operation)
}

fn resolve_path(
    request: &FirstPartyCapabilityRequest,
    path: &str,
    operation: FilesystemOperation,
) -> Result<ResolvedPath, FirstPartyCapabilityError> {
    let scoped_path = ScopedPath::new(scoped_path_input(path)).map_err(|_| input_error())?;
    if is_sensitive_scoped_path(scoped_path.as_str()) {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    let mounts = request.mounts.as_ref().ok_or_else(|| {
        FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied)
    })?;
    let (virtual_path, grant) = mounts
        .resolve_with_grant(&scoped_path)
        .map_err(|_| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied))?;
    if !operation_allowed(&grant.permissions, operation) {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    Ok(ResolvedPath {
        scoped_path,
        virtual_path,
        grant: grant.clone(),
    })
}

fn scoped_path_input(path: &str) -> String {
    if path == "." || path.is_empty() {
        DEFAULT_SCOPED_ROOT.to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", DEFAULT_SCOPED_ROOT, path.trim_start_matches("./"))
    }
}

fn operation_allowed(
    permissions: &ironclaw_host_api::MountPermissions,
    operation: FilesystemOperation,
) -> bool {
    match operation {
        FilesystemOperation::ReadFile => permissions.read,
        FilesystemOperation::WriteFile | FilesystemOperation::AppendFile => permissions.write,
        FilesystemOperation::ListDir => permissions.list,
        FilesystemOperation::Stat => permissions.read || permissions.list,
        FilesystemOperation::Delete => permissions.delete,
        FilesystemOperation::CreateDirAll => permissions.write,
        FilesystemOperation::MountLocal => false,
    }
}

async fn stat_optional(
    request: &FirstPartyCapabilityRequest,
    path: &VirtualPath,
) -> Result<Option<FileStat>, FirstPartyCapabilityError> {
    match request.filesystem.stat(path).await {
        Ok(stat) => Ok(Some(stat)),
        Err(FilesystemError::NotFound { .. }) => Ok(None),
        Err(error) => Err(filesystem_error(error)),
    }
}

async fn create_parent_dir(
    request: &FirstPartyCapabilityRequest,
    path: &VirtualPath,
) -> Result<(), FirstPartyCapabilityError> {
    let Some(parent) = virtual_parent(path)? else {
        return Ok(());
    };
    request
        .filesystem
        .create_dir_all(&parent)
        .await
        .map_err(filesystem_error)
}

fn virtual_parent(path: &VirtualPath) -> Result<Option<VirtualPath>, FirstPartyCapabilityError> {
    let raw = path.as_str().trim_end_matches('/');
    let Some((parent, _leaf)) = raw.rsplit_once('/') else {
        return Ok(None);
    };
    if parent.is_empty() {
        return Ok(None);
    }
    VirtualPath::new(parent)
        .map(Some)
        .map_err(|_| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied))
}

async fn collect_list_entries(
    request: &FirstPartyCapabilityRequest,
    root: &ResolvedPath,
    recursive: bool,
    max_depth: usize,
) -> Result<Vec<ListEntry>, FirstPartyCapabilityError> {
    let mut output = Vec::new();
    let mut stack = vec![(root.virtual_path.clone(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let entries = request
            .filesystem
            .list_dir(&dir)
            .await
            .map_err(filesystem_error)?;
        for entry in entries {
            visited += 1;
            if visited > MAX_VISITED_ENTRIES {
                return Err(FirstPartyCapabilityError::new(
                    RuntimeDispatchErrorKind::Resource,
                ));
            }
            let relative = virtual_to_relative(&root.virtual_path, &entry.path)?;
            let is_dir = entry.file_type == FileType::Directory;
            let scoped_path = scoped_child_path(&root.scoped_path, &relative);
            let is_sensitive = is_sensitive_scoped_path(&scoped_path);
            let display = if is_dir && recursive && is_sensitive {
                format!("{relative} [sensitive - access blocked]")
            } else if is_dir {
                format!("{relative}/")
            } else {
                let stat = request
                    .filesystem
                    .stat(&entry.path)
                    .await
                    .map_err(filesystem_error)?;
                format!("{} ({})", relative, format_size(stat.len))
            };
            output.push(ListEntry { display, is_dir });
            if recursive
                && is_dir
                && depth < max_depth
                && !is_sensitive
                && !is_excluded_name(entry.name.as_str())
            {
                stack.push((entry.path, depth + 1));
            }
            if output.len() > MAX_DIR_ENTRIES {
                return Ok(output);
            }
        }
    }
    Ok(output)
}

fn sort_list_entries(entries: &mut [ListEntry]) {
    entries.sort_by(|left, right| match (left.is_dir, right.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => left.display.cmp(&right.display),
    });
}

async fn walk_entries(
    request: &FirstPartyCapabilityRequest,
    root: &ResolvedPath,
    mut visit: impl FnMut(&DirEntry, &str) -> Result<bool, FirstPartyCapabilityError>,
) -> Result<(), FirstPartyCapabilityError> {
    let mut stack = vec![root.virtual_path.clone()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        let entries = request
            .filesystem
            .list_dir(&dir)
            .await
            .map_err(filesystem_error)?;
        for entry in entries {
            visited += 1;
            if visited > MAX_VISITED_ENTRIES {
                return Err(FirstPartyCapabilityError::new(
                    RuntimeDispatchErrorKind::Resource,
                ));
            }
            let relative = virtual_to_relative(&root.virtual_path, &entry.path)?;
            let keep_going = visit(&entry, &relative)?;
            let scoped_path = scoped_child_path(&root.scoped_path, &relative);
            if entry.file_type == FileType::Directory
                && !is_excluded_name(entry.name.as_str())
                && !is_sensitive_scoped_path(&scoped_path)
            {
                stack.push(entry.path.clone());
            }
            if !keep_going {
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn walk_files(
    request: &FirstPartyCapabilityRequest,
    root: &ResolvedPath,
    root_stat: FileStat,
    mut include: impl FnMut(&str) -> bool,
    mut visit: impl FnMut(&str, &[u8], Option<SystemTime>) -> Result<bool, FirstPartyCapabilityError>,
) -> Result<(), FirstPartyCapabilityError> {
    let mut total_bytes = 0u64;
    if root_stat.file_type == FileType::File {
        let relative = root_file_relative(&root.scoped_path);
        if include(&relative)
            && !visit_file(
                request,
                &root.virtual_path,
                &relative,
                root_stat,
                &mut total_bytes,
                &mut visit,
            )
            .await?
        {
            return Ok(());
        }
        return Ok(());
    }

    let mut stack = vec![root.virtual_path.clone()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        let entries = request
            .filesystem
            .list_dir(&dir)
            .await
            .map_err(filesystem_error)?;
        for entry in entries {
            visited += 1;
            if visited > MAX_VISITED_ENTRIES {
                return Err(FirstPartyCapabilityError::new(
                    RuntimeDispatchErrorKind::Resource,
                ));
            }
            let relative = virtual_to_relative(&root.virtual_path, &entry.path)?;
            let scoped_path = scoped_child_path(&root.scoped_path, &relative);
            if is_sensitive_scoped_path(&scoped_path) {
                continue;
            }
            match entry.file_type {
                FileType::Directory => {
                    if !is_excluded_name(entry.name.as_str()) {
                        stack.push(entry.path);
                    }
                }
                FileType::File => {
                    if !include(&relative) {
                        continue;
                    }
                    let stat = request
                        .filesystem
                        .stat(&entry.path)
                        .await
                        .map_err(filesystem_error)?;
                    if stat.sensitive {
                        continue;
                    }
                    if !visit_file(
                        request,
                        &entry.path,
                        &relative,
                        stat,
                        &mut total_bytes,
                        &mut visit,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                }
                FileType::Symlink | FileType::Other => {}
            }
        }
    }
    Ok(())
}

async fn visit_file(
    request: &FirstPartyCapabilityRequest,
    path: &VirtualPath,
    relative: &str,
    stat: FileStat,
    total_bytes: &mut u64,
    visit: &mut impl FnMut(&str, &[u8], Option<SystemTime>) -> Result<bool, FirstPartyCapabilityError>,
) -> Result<bool, FirstPartyCapabilityError> {
    if stat.len > MAX_READ_SIZE {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::Resource,
        ));
    }
    *total_bytes = total_bytes.saturating_add(stat.len);
    if *total_bytes > 16 * 1024 * 1024 {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::Resource,
        ));
    }
    let bytes = request
        .filesystem
        .read_file(path)
        .await
        .map_err(filesystem_error)?;
    visit(relative, &bytes, stat.modified)
}

fn root_file_relative(path: &ScopedPath) -> String {
    path.as_str()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn virtual_to_relative(
    root: &VirtualPath,
    path: &VirtualPath,
) -> Result<String, FirstPartyCapabilityError> {
    let target = root.as_str().trim_end_matches('/');
    let raw = path.as_str();
    if raw == target {
        return Ok(String::new());
    }
    raw.strip_prefix(&format!("{target}/"))
        .map(ToString::to_string)
        .ok_or_else(|| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied))
}

fn validate_relative_pattern(pattern: &str) -> Result<(), FirstPartyCapabilityError> {
    if pattern.starts_with('/') || pattern.split('/').any(|segment| segment == "..") {
        return Err(input_error());
    }
    Ok(())
}

fn is_excluded_name(name: &str) -> bool {
    DEFAULT_EXCLUDED_DIRS.contains(&name)
}

fn is_excluded_relative_path(path: &str) -> bool {
    path.split('/').any(is_excluded_name)
}

fn type_filter_matches(path: &str, type_filter: &str) -> bool {
    let extension = path
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or_default();
    match type_filter {
        "rust" | "rs" => extension == "rs",
        "py" | "python" => extension == "py",
        "js" | "javascript" => extension == "js" || extension == "jsx",
        "ts" | "typescript" => extension == "ts" || extension == "tsx",
        other => extension == other,
    }
}

fn build_grep_output(
    output_mode: &str,
    mut results: Vec<GrepFileResult>,
    offset: usize,
    head_limit: Option<usize>,
    had_context: bool,
) -> Value {
    let effective_limit = match head_limit {
        Some(0) => usize::MAX,
        Some(value) => value,
        None => DEFAULT_HEAD_LIMIT,
    };
    match output_mode {
        "files_with_matches" => {
            let total = results.len();
            let files = results
                .into_iter()
                .skip(offset)
                .take(effective_limit)
                .map(|result| result.relative)
                .collect::<Vec<_>>();
            json!({
                "files": files,
                "count": files.len(),
                "truncated": total > offset.saturating_add(effective_limit)
            })
        }
        "count" => {
            let total_count = results.len();
            let page = results
                .drain(..)
                .skip(offset)
                .take(effective_limit)
                .collect::<Vec<_>>();
            let total = page.iter().map(|result| result.count).sum::<usize>();
            json!({
                "counts": page.into_iter().map(|result| json!({
                    "file": result.relative,
                    "count": result.count
                })).collect::<Vec<_>>(),
                "total": total,
                "truncated": total_count > offset.saturating_add(effective_limit)
            })
        }
        _ => {
            let mut lines = Vec::new();
            for result in results {
                for line in result.lines {
                    let separator = if line.is_match || !had_context {
                        ':'
                    } else {
                        '-'
                    };
                    lines.push(format!(
                        "{}{}{}{}{}",
                        result.relative, separator, line.number, separator, line.text
                    ));
                }
            }
            let raw_len = lines.iter().map(|line| line.len() + 1).sum::<usize>();
            let page = lines
                .iter()
                .skip(offset)
                .take(effective_limit)
                .cloned()
                .collect::<Vec<_>>();
            let mut content = page.join("\n");
            let mut truncated =
                raw_len > MAX_OUTPUT_SIZE || lines.len() > offset.saturating_add(effective_limit);
            if content.len() > MAX_OUTPUT_SIZE {
                content.truncate(previous_char_boundary(&content, MAX_OUTPUT_SIZE));
                truncated = true;
            }
            json!({ "content": content, "truncated": truncated })
        }
    }
}

fn line_matches(
    content: &str,
    regex: &regex::Regex,
    before_context: usize,
    after_context: usize,
) -> Vec<GrepLine> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut include = std::collections::BTreeSet::new();
    let mut matched = std::collections::BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if regex.is_match(line) {
            matched.insert(index);
            let start = index.saturating_sub(before_context);
            let end = (index + after_context + 1).min(lines.len());
            for item in start..end {
                include.insert(item);
            }
        }
    }
    include
        .into_iter()
        .map(|index| GrepLine {
            number: index + 1,
            text: lines[index].to_string(),
            is_match: matched.contains(&index) || (before_context == 0 && after_context == 0),
        })
        .collect::<Vec<_>>()
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}

fn required_str<'a>(input: &'a Value, field: &str) -> Result<&'a str, FirstPartyCapabilityError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(input_error)
}

fn optional_usize(input: &Value, field: &str) -> Result<Option<usize>, FirstPartyCapabilityError> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(input_error)
        })
        .transpose()
}

fn optional_usize_allow_zero(
    input: &Value,
    field: &str,
) -> Result<Option<usize>, FirstPartyCapabilityError> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(input_error)
        })
        .transpose()
}

fn reject_binary_probe(bytes: &[u8]) -> Result<(), FirstPartyCapabilityError> {
    if detect_encoding(bytes) == FileEncoding::Utf16Le {
        return Ok(());
    }
    let probe_len = bytes.len().min(8192);
    if bytes[..probe_len].contains(&0) {
        return Err(guest_error());
    }
    Ok(())
}

fn decode_text(
    bytes: &[u8],
) -> Result<(String, FileEncoding, LineEnding), FirstPartyCapabilityError> {
    let encoding = detect_encoding(bytes);
    let raw = match encoding {
        FileEncoding::Utf8 => String::from_utf8(bytes.to_vec()).map_err(|_| guest_error())?,
        FileEncoding::Utf16Le => {
            let data = bytes.get(2..).unwrap_or_default();
            let units = data
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units).map_err(|_| guest_error())?
        }
    };
    let line_ending = detect_line_ending(&raw);
    Ok((
        raw.replace("\r\n", "\n").replace('\r', "\n"),
        encoding,
        line_ending,
    ))
}

fn encode_text(content: &str, encoding: FileEncoding, line_ending: LineEnding) -> Vec<u8> {
    let output = match line_ending {
        LineEnding::Lf => content.to_string(),
        LineEnding::CrLf => content.replace('\n', "\r\n"),
        LineEnding::Cr => content.replace('\n', "\r"),
    };
    match encoding {
        FileEncoding::Utf8 => output.into_bytes(),
        FileEncoding::Utf16Le => {
            let mut bytes = vec![0xFF, 0xFE];
            for unit in output.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        }
    }
}

fn detect_encoding(bytes: &[u8]) -> FileEncoding {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        FileEncoding::Utf16Le
    } else {
        FileEncoding::Utf8
    }
}

fn detect_line_ending(content: &str) -> LineEnding {
    let crlf = content.matches("\r\n").count();
    let cr_only = content.matches('\r').count().saturating_sub(crlf);
    let lf_only = content.matches('\n').count().saturating_sub(crlf);
    if crlf >= lf_only && crlf >= cr_only {
        if crlf == 0 {
            LineEnding::Lf
        } else {
            LineEnding::CrLf
        }
    } else if cr_only > lf_only {
        LineEnding::Cr
    } else {
        LineEnding::Lf
    }
}

fn replace_content(
    content: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
    match_count: usize,
) -> Result<(String, usize), FirstPartyCapabilityError> {
    if replace_all {
        let mut matches = Vec::new();
        let mut search_offset = 0usize;
        while let Some(item) = find_match_from(content, old_string, search_offset) {
            if item.end <= item.start {
                return Err(guest_error());
            }
            search_offset = item.end;
            matches.push((item.start, item.end));
        }
        if matches.len() != match_count {
            return Err(guest_error());
        }
        let mut rebuilt = String::with_capacity(content.len());
        let mut last = 0usize;
        for (start, end) in matches {
            rebuilt.push_str(&content[last..start]);
            rebuilt.push_str(new_string);
            last = end;
        }
        rebuilt.push_str(&content[last..]);
        Ok((rebuilt, match_count))
    } else {
        let item = find_match(content, old_string).ok_or_else(guest_error)?;
        let mut rebuilt =
            String::with_capacity(content.len() - (item.end - item.start) + new_string.len());
        rebuilt.push_str(&content[..item.start]);
        rebuilt.push_str(new_string);
        rebuilt.push_str(&content[item.end..]);
        Ok((rebuilt, 1))
    }
}

fn find_match(haystack: &str, needle: &str) -> Option<FuzzyMatch> {
    find_match_from(haystack, needle, 0)
}

fn find_match_from(haystack: &str, needle: &str, start_offset: usize) -> Option<FuzzyMatch> {
    let search = haystack.get(start_offset..)?;
    if let Some(index) = search.find(needle) {
        let start = start_offset + index;
        return Some(FuzzyMatch {
            start,
            end: start + needle.len(),
        });
    }
    let needle_stripped = strip_trailing_whitespace(needle);
    let haystack_stripped = strip_trailing_whitespace(search);
    if let Some((start, end)) = find_normalized_span(search, &haystack_stripped, &needle_stripped) {
        return Some(FuzzyMatch {
            start: start_offset + start,
            end: start_offset + end,
        });
    }
    let needle_normalized = normalize_quotes(needle);
    let haystack_normalized = normalize_quotes(search);
    if let Some(index) = haystack_normalized.find(&needle_normalized) {
        let char_start = haystack_normalized[..index].chars().count();
        let char_len = needle_normalized.chars().count();
        let start = char_to_byte_idx(search, char_start)?;
        let end = char_to_byte_idx(search, char_start + char_len)?;
        return Some(FuzzyMatch {
            start: start_offset + start,
            end: start_offset + end,
        });
    }
    let needle_both = normalize_quotes(&needle_stripped);
    let haystack_both = normalize_quotes(&haystack_stripped);
    find_normalized_span(search, &haystack_both, &needle_both).map(|(start, end)| FuzzyMatch {
        start: start_offset + start,
        end: start_offset + end,
    })
}

fn count_matches(haystack: &str, needle: &str) -> (usize, MatchMethod) {
    let exact = haystack.matches(needle).count();
    if exact > 0 {
        return (exact, MatchMethod::Exact);
    }
    let needle_stripped = strip_trailing_whitespace(needle);
    let haystack_stripped = strip_trailing_whitespace(haystack);
    let stripped_count = haystack_stripped.matches(&needle_stripped).count();
    if stripped_count > 0 {
        return (stripped_count, MatchMethod::TrailingWhitespace);
    }
    let needle_normalized = normalize_quotes(needle);
    let haystack_normalized = normalize_quotes(haystack);
    let normalized_count = haystack_normalized.matches(&needle_normalized).count();
    if normalized_count > 0 {
        return (normalized_count, MatchMethod::QuoteNormalization);
    }
    let needle_both = normalize_quotes(&needle_stripped);
    let haystack_both = normalize_quotes(&haystack_stripped);
    let both_count = haystack_both.matches(&needle_both).count();
    if both_count > 0 {
        return (both_count, MatchMethod::Both);
    }
    (0, MatchMethod::Exact)
}

fn strip_trailing_whitespace(value: &str) -> String {
    value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_quotes(value: &str) -> String {
    value
        .replace(['\u{2018}', '\u{2019}', '\u{2032}'], "'")
        .replace(['\u{201C}', '\u{201D}', '\u{2033}'], "\"")
}

fn find_normalized_span(original: &str, normalized: &str, needle: &str) -> Option<(usize, usize)> {
    let index = normalized.find(needle)?;
    let char_index = normalized[..index].chars().count();
    let char_len = needle.chars().count();
    let start = map_normalized_char_to_original_byte(original, char_index)?;
    let end = map_normalized_char_to_original_byte(original, char_index + char_len)?;
    Some((start, end))
}

fn char_to_byte_idx(value: &str, char_index: usize) -> Option<usize> {
    if char_index == value.chars().count() {
        return Some(value.len());
    }
    value.char_indices().nth(char_index).map(|(index, _)| index)
}

fn map_normalized_char_to_original_byte(
    original: &str,
    normalized_char_index: usize,
) -> Option<usize> {
    if normalized_char_index == 0 {
        return Some(0);
    }
    let mut normalized_seen = 0usize;
    let mut original_byte = 0usize;
    for segment in original.split_inclusive('\n') {
        let (line, has_newline) = if let Some(stripped) = segment.strip_suffix('\n') {
            (stripped, true)
        } else {
            (segment, false)
        };
        let trimmed = line.trim_end();
        let trimmed_chars = trimmed.chars().count();
        if normalized_char_index <= normalized_seen + trimmed_chars {
            let within_line = normalized_char_index - normalized_seen;
            return Some(original_byte + char_to_byte_idx(line, within_line)?);
        }
        normalized_seen += trimmed_chars;
        original_byte += line.len();
        if has_newline {
            if normalized_char_index == normalized_seen + 1 {
                return Some(original_byte + 1);
            }
            normalized_seen += 1;
            original_byte += 1;
        }
    }
    if normalized_char_index == normalized_seen {
        Some(original_byte)
    } else {
        None
    }
}

fn previous_char_boundary(value: &str, mut end: usize) -> usize {
    end = end.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn is_workspace_path(path: &str) -> bool {
    let normalized = path.trim_start_matches('/');
    let relative = normalized.strip_prefix("workspace/").unwrap_or(normalized);
    let filename = relative.rsplit('/').next().unwrap_or(relative);
    WORKSPACE_FILES.contains(&filename)
        || relative.starts_with("daily/")
        || relative.starts_with("context/")
}

fn scoped_child_path(root: &ScopedPath, relative: &str) -> String {
    if relative.is_empty() {
        root.as_str().to_string()
    } else {
        format!("{}/{}", root.as_str().trim_end_matches('/'), relative)
    }
}

fn is_sensitive_scoped_path(path: &str) -> bool {
    is_sensitive_path(Path::new(path))
}

fn filesystem_error(error: FilesystemError) -> FirstPartyCapabilityError {
    match error {
        FilesystemError::Contract(_) => input_error(),
        FilesystemError::PermissionDenied { .. }
        | FilesystemError::MountNotFound { .. }
        | FilesystemError::PathOutsideMount { .. }
        | FilesystemError::SymlinkEscape { .. }
        | FilesystemError::MountConflict { .. } => {
            FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied)
        }
        FilesystemError::NotFound { .. } => guest_error(),
        FilesystemError::Backend { .. } => guest_error(),
    }
}
