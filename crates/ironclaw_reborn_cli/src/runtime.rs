use ironclaw_reborn_config::RebornBootConfig;

/// Side-effect-free runtime-shell snapshot for the standalone Reborn binary.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeShellReport {
    config: RebornBootConfig,
    driver_registry_initialized: bool,
}

impl RuntimeShellReport {
    pub(crate) fn initialize(config: RebornBootConfig) -> Self {
        let _registry = ironclaw_reborn::driver_registry::DriverRegistry::new();
        Self {
            config,
            driver_registry_initialized: true,
        }
    }

    pub(crate) fn print(&self) {
        println!("IronClaw Reborn runtime shell");
        println!("binary: ironclaw-reborn");
        println!("version: {}", env!("CARGO_PKG_VERSION"));
        println!("reborn_home: {}", self.config.home().path().display());
        println!("home_source: {}", self.config.home().source_label());
        println!("profile: {}", self.config.profile());
        println!("v1_state: not-used");
        println!("driver_registry: initialized");
        println!(
            "runtime_shell: {}",
            if self.driver_registry_initialized {
                "initialized"
            } else {
                "unavailable"
            }
        );
    }
}
