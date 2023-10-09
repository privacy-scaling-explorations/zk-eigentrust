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
use eigentrust::error::EigenError;
use env_logger::{init_from_env, Env};
use fs::load_config;
use log::info;

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	dotenv().ok();
	init_from_env(Env::default().filter_or("LOG_LEVEL", "info"));

	match Cli::parse().mode {
		Mode::Attest(attest_data) => handle_attest(attest_data).await?,
		Mode::Attestations => handle_attestations().await?,
		Mode::Bandada(bandada_data) => handle_bandada(bandada_data).await?,
		Mode::Deploy => handle_deploy().await?,
		Mode::ETProof => handle_et_proof().await?,
		Mode::ETProvingKey => handle_et_pk()?,
		Mode::ETVerify => handle_et_verify().await?,
		Mode::KZGParams(kzg_params_data) => handle_params(kzg_params_data)?,
		Mode::LocalScores => handle_scores(AttestationsOrigin::Local).await?,
		Mode::Scores => handle_scores(AttestationsOrigin::Fetch).await?,
		Mode::Show => info!("Client config:\n{:#?}", load_config()?),
		Mode::ThProof(th_proof_data) => handle_th_proof(th_proof_data).await?,
		Mode::ThProvingKey => handle_th_pk().await?,
		Mode::ThVerify => handle_th_verify().await?,
		Mode::Update(update_data) => handle_update(update_data)?,
	};

	Ok(())
}
