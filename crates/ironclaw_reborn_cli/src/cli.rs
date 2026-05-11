use clap::Parser;

use crate::commands::Command;

#[derive(Debug, Parser)]
#[command(
    name = "ironclaw-reborn",
    about = "Standalone IronClaw Reborn runtime",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

pub(crate) fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let context = crate::context::RebornCliContext::resolve_from_env()?;
    cli.command.execute(context)
}
