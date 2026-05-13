use wasmtime::ResourceLimiter;

#[derive(Debug)]
pub(crate) struct WasmResourceLimiter {
    memory_limit: u64,
    memory_used: u64,
    pending_memory_growth: u64,
    max_tables: u32,
    max_instances: u32,
    max_memories: u32,
}

impl WasmResourceLimiter {
    pub(crate) fn new(memory_limit: u64) -> Self {
        Self {
            memory_limit,
            memory_used: 0,
            pending_memory_growth: 0,
            max_tables: 10,
            max_instances: 10,
            max_memories: 10,
        }
    }
}

impl ResourceLimiter for WasmResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        self.pending_memory_growth = 0;

        let current = current as u64;
        let desired = desired as u64;
        let growth = desired.saturating_sub(current);
        let total_memory = self.memory_used.saturating_add(growth);
        if total_memory > self.memory_limit {
            tracing::warn!(
                current,
                desired,
                growth,
                used = self.memory_used,
                total = total_memory,
                limit = self.memory_limit,
                "WASM ProductAdapter memory growth denied"
            );
            return Ok(false);
        }

        self.memory_used = total_memory;
        self.pending_memory_growth = growth;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> Result<(), wasmtime::Error> {
        self.memory_used = self.memory_used.saturating_sub(self.pending_memory_growth);
        self.pending_memory_growth = 0;
        Ok(())
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        Ok(desired <= 10_000)
    }

    fn instances(&self) -> usize {
        self.max_instances as usize
    }

    fn tables(&self) -> usize {
        self.max_tables as usize
    }

    fn memories(&self) -> usize {
        self.max_memories as usize
    }
}
