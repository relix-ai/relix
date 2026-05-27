use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "relix",
    about = "The local LLM API gateway that protects AI coding agents.",
    version,
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the gateway, listening on a local port.
    Start {
        /// Port to listen on.
        #[arg(long, default_value_t = 7777, env = "RELIX_PORT")]
        port: u16,

        /// Upstream LLM API base URL (defaults to Anthropic).
        #[arg(
            long,
            default_value = "https://api.anthropic.com",
            env = "RELIX_UPSTREAM"
        )]
        upstream: String,

        /// Path to rules directory or single YAML file.
        #[arg(long, default_value = "rules", env = "RELIX_RULES")]
        rules: PathBuf,

        /// Path to audit log file (jsonl).
        #[arg(long, default_value = "~/.relix/audit.jsonl", env = "RELIX_AUDIT")]
        audit: String,
    },

    /// Print the loaded ruleset and exit.
    Rules {
        #[arg(long, default_value = "rules")]
        path: PathBuf,
    },

    /// Tail the audit log.
    Logs {
        #[arg(long, default_value = "~/.relix/audit.jsonl")]
        audit: String,
    },
}
