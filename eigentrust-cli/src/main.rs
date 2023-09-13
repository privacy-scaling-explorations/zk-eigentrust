//! # ZK Eigentrust CLI
//!
//! This crate provides a CLI interface to use the `eigentrust` library.

#![warn(trivial_casts)]
#![deny(
	absolute_paths_not_starting_with_crate, deprecated, future_incompatible, missing_docs,
	nonstandard_style, unreachable_code, unreachable_patterns
)]
#![forbid(unsafe_code)]
#![deny(
	// Complexity
 	clippy::unnecessary_cast,
	clippy::needless_question_mark,
	// Pedantic
 	clippy::cast_lossless,
 	clippy::cast_possible_wrap,
	// Perf
	clippy::redundant_clone,
	// Restriction
 	clippy::panic,
	// Style
 	clippy::let_and_return,
 	clippy::needless_borrow
)]

mod bandada;
mod cli;
mod fs;

use clap::Parser;
use cli::*;
use dotenv::dotenv;
use eigentrust::{error::EigenError, ClientConfig};
use env_logger::{init_from_env, Env};
use fs::load_config;
use log::info;

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	dotenv().ok();
	init_from_env(Env::default().filter_or("LOG_LEVEL", "info"));
	let mut config: ClientConfig = load_config()?;

	match Cli::parse().mode {
		Mode::Attest(attest_data) => handle_attest(config, attest_data).await?,
		Mode::Attestations => handle_attestations(config).await?,
		Mode::Bandada(bandada_data) => handle_bandada(&config, bandada_data).await?,
		Mode::Deploy => handle_deploy(config).await?,
		Mode::LocalScores => handle_scores(config, AttestationsOrigin::Local).await?,
		Mode::Proof => handle_proof(config).await?,
		Mode::Scores => handle_scores(config, AttestationsOrigin::Fetch).await?,
		Mode::Show => info!("Client config:\n{:#?}", config),
		Mode::Update(update_data) => handle_update(&mut config, update_data)?,
		Mode::Verify => info!("Not implemented yet."),
		Mode::GenerateParams(gen_params_data) => handle_gen_params(gen_params_data)?,
		Mode::GenerateEtProvingKey => handle_gen_et_pk()?,
	};

	Ok(())
}
