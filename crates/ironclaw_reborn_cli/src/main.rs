mod cli;
mod runtime;

fn main() -> anyhow::Result<()> {
    cli::run()
}
