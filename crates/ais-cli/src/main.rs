//! AIS-Core command line interface.

mod cli;
mod commands;
mod error;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::error::CliError;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::SignModel(args) => commands::sign_model::run(args),
        Command::VerifyModel(args) => commands::verify_model::run(args),
        Command::ValidateAudit(args) => commands::validate_audit::run(args),
    }
}
