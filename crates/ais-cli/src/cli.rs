//! Command line argument definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Minimal deterministic CLI for AIS-Core.
#[derive(Debug, Parser)]
#[command(name = "ais-cli")]
#[command(about = "Minimal deterministic AIS-Core CLI")]
pub struct Cli {
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported AIS-Core MVP commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign a model file and write an AI certificate.
    SignModel(SignModelArgs),

    /// Verify a model file against an AI certificate.
    VerifyModel(VerifyModelArgs),

    /// Validate an audit chain file.
    ValidateAudit(ValidateAuditArgs),
}

/// Arguments for `sign-model`.
#[derive(Debug, Args)]
pub struct SignModelArgs {
    /// Model file to hash and certify.
    #[arg(long)]
    pub model: PathBuf,

    /// Raw 32-byte Ed25519 issuer private key file.
    #[arg(long)]
    pub issuer: PathBuf,

    /// Output certificate file.
    #[arg(long)]
    pub output: PathBuf,
}

/// Arguments for `verify-model`.
#[derive(Debug, Args)]
pub struct VerifyModelArgs {
    /// Model file to verify.
    #[arg(long)]
    pub model: PathBuf,

    /// AI certificate file.
    #[arg(long)]
    pub cert: PathBuf,
}

/// Arguments for `validate-audit`.
#[derive(Debug, Args)]
pub struct ValidateAuditArgs {
    /// Audit chain file.
    #[arg(long)]
    pub input: PathBuf,
}
