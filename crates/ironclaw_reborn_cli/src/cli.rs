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
    Cli::parse().command.execute()
}
