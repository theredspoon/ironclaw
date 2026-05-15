use clap::Args;
use ironclaw_reborn_config::RebornBootConfig;

use crate::context::RebornCliContext;

#[derive(Debug, Args)]
pub(crate) struct RunCommand;

impl RunCommand {
    pub(crate) fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        RuntimeShellReport::initialize(context).print();
        Ok(())
    }
}

/// Side-effect-free runtime-shell snapshot for the standalone Reborn binary.
#[derive(Debug, Clone)]
struct RuntimeShellReport {
    config: RebornBootConfig,
    driver_registry_initialized: bool,
    planned_default_profile_available: bool,
}

impl RuntimeShellReport {
    fn initialize(context: RebornCliContext) -> Self {
        let mut registry = ironclaw_reborn::driver_registry::DriverRegistry::new();
        let text_only_registered = ironclaw_reborn::register_default_text_only_driver(
            &mut registry,
            ironclaw_reborn::TextOnlyModelReplyDriverConfig::default(),
        )
        .is_ok();
        let planned_registered = ironclaw_reborn::build_loop_family_registry()
            .map(|family_registry| {
                ironclaw_reborn::register_default_planned_driver(&mut registry, family_registry)
                    .is_ok()
            })
            .unwrap_or(false);
        let planned_default_profile_available =
            ironclaw_reborn::default_planned_run_profile_resolver().is_ok();
        Self {
            config: context.boot_config().clone(),
            driver_registry_initialized: text_only_registered && planned_registered,
            planned_default_profile_available,
        }
    }

    fn print(&self) {
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
        println!(
            "planned_default_profile: {}",
            if self.planned_default_profile_available {
                "available"
            } else {
                "unavailable"
            }
        );
    }
}
