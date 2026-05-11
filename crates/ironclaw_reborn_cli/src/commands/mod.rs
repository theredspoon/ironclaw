use clap::Subcommand;

pub(crate) mod doctor;
pub(crate) mod run;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Check Reborn binary configuration without creating state.
    Doctor(doctor::DoctorCommand),
    /// Initialize the minimal Reborn runtime shell and exit.
    Run(run::RunCommand),
}

impl Command {
    pub(crate) fn execute(self, context: crate::context::RebornCliContext) -> anyhow::Result<()> {
        match self {
            Self::Doctor(command) => command.execute(context),
            Self::Run(command) => command.execute(context),
        }
    }
}
