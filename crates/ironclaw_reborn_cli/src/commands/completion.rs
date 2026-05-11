use std::io::{self, Write};

use clap::Args;
use clap_complete::{Shell, generate};

#[derive(Debug, Args)]
pub(crate) struct CompletionCommand {
    /// The shell to generate completions for.
    #[arg(value_enum, long)]
    shell: Shell,
}

impl CompletionCommand {
    pub(crate) fn execute(self) -> anyhow::Result<()> {
        let mut command = crate::cli::command();
        let bin_name = command.get_name().to_string();

        if self.shell == Shell::Zsh {
            let mut buffer = Vec::new();
            generate(self.shell, &mut command, bin_name.clone(), &mut buffer);
            let script = String::from_utf8(buffer)?;

            let bare = format!("compdef _{0} {0}", bin_name);
            let guarded = format!("(( $+functions[compdef] )) && compdef _{0} {0}", bin_name);
            io::stdout().write_all(script.replace(&bare, &guarded).as_bytes())?;
        } else {
            generate(self.shell, &mut command, bin_name, &mut io::stdout());
        }

        Ok(())
    }
}
