use clap::Parser;
use anyhow::Result;

mod cli;
mod commands;
mod attestation;
mod storage;
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    let app = cli::Cli::parse();
    match app.command {
        cli::Commands::Keygen(a)   => commands::keygen::execute(a)?,
        cli::Commands::Run(a)      => commands::run::execute(a).await?,
        cli::Commands::History(a)  => commands::history::execute(a).await?,
        cli::Commands::Timeline(a) => commands::timeline::execute(a).await?,
        cli::Commands::Verify(a)   => commands::verify::execute(a).await?,
        cli::Commands::Export(a)   => commands::export::execute(a).await?,
    }
    Ok(())
}
