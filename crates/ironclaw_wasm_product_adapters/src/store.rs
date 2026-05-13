use std::time::{Duration, Instant};

use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::bindings;
use crate::config::{MAX_LOG_MESSAGE_BYTES, MAX_LOGS_PER_EXECUTION};
use crate::limiter::WasmResourceLimiter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentLogRecord {
    pub level: ComponentLogLevel,
    pub message: String,
}

pub(crate) struct StoreData {
    pub(crate) limiter: WasmResourceLimiter,
    wasi: WasiCtx,
    table: ResourceTable,
    pub(crate) logs: Vec<ComponentLogRecord>,
    deadline: Option<Instant>,
}

impl StoreData {
    pub(crate) fn new(memory_limit: u64, timeout: Duration) -> Self {
        Self {
            limiter: WasmResourceLimiter::new(memory_limit),
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            logs: Vec::new(),
            deadline: Instant::now().checked_add(timeout),
        }
    }

    pub(crate) fn deadline_exceeded(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

impl WasiView for StoreData {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl bindings::near::product_adapter::product_adapter_host::Host for StoreData {
    fn log(
        &mut self,
        level: bindings::near::product_adapter::product_adapter_host::LogLevel,
        message: String,
    ) {
        if self.logs.len() >= MAX_LOGS_PER_EXECUTION {
            return;
        }
        let level = match level {
            bindings::near::product_adapter::product_adapter_host::LogLevel::Trace => {
                ComponentLogLevel::Trace
            }
            bindings::near::product_adapter::product_adapter_host::LogLevel::Debug => {
                ComponentLogLevel::Debug
            }
            bindings::near::product_adapter::product_adapter_host::LogLevel::Info => {
                ComponentLogLevel::Info
            }
            bindings::near::product_adapter::product_adapter_host::LogLevel::Warn => {
                ComponentLogLevel::Warn
            }
            bindings::near::product_adapter::product_adapter_host::LogLevel::Error => {
                ComponentLogLevel::Error
            }
        };
        self.logs.push(ComponentLogRecord {
            level,
            message: truncate_log_message(message),
        });
    }

    fn now_millis(&mut self) -> u64 {
        chrono::Utc::now().timestamp_millis().max(0) as u64
    }

    fn http_egress(
        &mut self,
        _request: bindings::near::product_adapter::product_adapter_host::EgressRequest,
    ) -> Result<
        bindings::near::product_adapter::product_adapter_host::EgressResponse,
        bindings::near::product_adapter::product_adapter_host::EgressError,
    > {
        Err(bindings::near::product_adapter::product_adapter_host::EgressError {
            kind: bindings::near::product_adapter::product_adapter_host::EgressErrorKind::PolicyDenied,
            message: "host http egress is not wired for ProductAdapter components yet".to_string(),
        })
    }
}

fn truncate_log_message(message: String) -> String {
    if message.len() <= MAX_LOG_MESSAGE_BYTES {
        return message;
    }

    let mut end = MAX_LOG_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::{MAX_LOG_MESSAGE_BYTES, truncate_log_message};

    #[test]
    fn truncate_log_message_respects_utf8_boundaries() {
        let message = "é".repeat(MAX_LOG_MESSAGE_BYTES);
        let truncated = truncate_log_message(message);
        assert!(truncated.len() <= MAX_LOG_MESSAGE_BYTES);
        assert!(truncated.is_char_boundary(truncated.len()));
    }
}
