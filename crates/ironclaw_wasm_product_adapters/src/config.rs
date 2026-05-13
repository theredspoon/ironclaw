use std::time::Duration;

pub const PRODUCT_ADAPTER_WIT_VERSION: &str = "0.1.0";

pub(crate) const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) const MAX_LOGS_PER_EXECUTION: usize = 1_000;
pub(crate) const MAX_LOG_MESSAGE_BYTES: usize = 4 * 1024;

const DEFAULT_MEMORY_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_FUEL: u64 = 500_000_000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct ProductAdapterComponentLimits {
    pub memory_bytes: u64,
    pub fuel: u64,
    pub timeout: Duration,
}

impl Default for ProductAdapterComponentLimits {
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            fuel: DEFAULT_FUEL,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl ProductAdapterComponentLimits {
    pub fn with_memory_bytes(mut self, memory_bytes: u64) -> Self {
        self.memory_bytes = memory_bytes;
        self
    }

    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = fuel;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProductAdapterComponentRuntimeConfig {
    pub default_limits: ProductAdapterComponentLimits,
}

impl ProductAdapterComponentRuntimeConfig {
    pub fn for_testing() -> Self {
        Self {
            default_limits: ProductAdapterComponentLimits::default()
                .with_memory_bytes(1024 * 1024)
                .with_fuel(100_000)
                .with_timeout(Duration::from_secs(5)),
        }
    }
}
