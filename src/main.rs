use anyhow::Result;
use clap::Parser;

mod cli;
mod commands;

#[tokio::main]
async fn main() -> Result<()> {
    let app = cli::Cli::parse();
    let code = match app.command {
        cli::Commands::Keygen(a) => commands::keygen::execute(a)?,
        cli::Commands::Run(a) => commands::run::execute(a).await?,
        cli::Commands::History(a) => commands::history::execute(a).await?,
        cli::Commands::Timeline(a) => commands::timeline::execute(a).await?,
        cli::Commands::Verify(a) => commands::verify::execute(a).await?,
        cli::Commands::Export(a) => commands::export::execute(a).await?,
        cli::Commands::Rebuild(a) => commands::rebuild::execute(a).await?,
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
