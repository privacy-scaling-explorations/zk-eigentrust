mod bandada;
mod cli;

use clap::Parser;
use cli::*;
use dotenv::dotenv;
use eigen_trust_client::{
	error::EigenError,
	eth::{deploy_as, gen_as_bindings},
	fs::load_config,
	Client, ClientConfig,
};
use env_logger::{init_from_env, Env};
use log::info;

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	dotenv().ok();
	init_from_env(Env::default().filter_or("LOG_LEVEL", "info"));
	let mut config: ClientConfig = load_config()?;

	match Cli::parse().mode {
		Mode::Attest(attest_data) => {
			let attestation = attest_data.to_attestation(&config)?;
			info!("Attesting...\n{:#?}", attestation);

			let client = Client::new(config);
			client.attest(attestation).await?;
		},
		Mode::Attestations => handle_attestations(config).await?,
		Mode::Bandada(bandada_data) => handle_bandada(&config, bandada_data).await?,
		Mode::Compile => gen_as_bindings()?,
		Mode::Deploy => {
			let client = Client::new(config);
			let as_address = deploy_as(client.get_signer()).await?;
			info!("AttestationStation deployed at {:?}", as_address);
		},
		Mode::LocalScores => handle_scores(config, AttestationsOrigin::Local).await?,
		Mode::Proof => info!("Not implemented yet."),
		Mode::Scores => handle_scores(config, AttestationsOrigin::Fetch).await?,
		Mode::Show => info!("Client config:\n{:#?}", config),
		Mode::Update(update_data) => handle_update(&mut config, update_data)?,
		Mode::Verify => info!("Not implemented yet."),
	};

	Ok(())
}
