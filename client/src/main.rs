mod bandada;
mod cli;

use clap::Parser;
use cli::*;
use dotenv::dotenv;
use eigen_trust_client::{
	eth::{compile_att_station, deploy_as, deploy_verifier},
	fs::read_json,
	Client, ClientConfig,
};
use env_logger::{init_from_env, Env};
use log::{error, info};

#[tokio::main]
async fn main() {
	// Load .env and initialize logger
	dotenv().ok();
	init_from_env(Env::default().filter_or("LOG_LEVEL", "info"));

	// Read configuration
	let mut config: ClientConfig = match read_json("client-config") {
		Ok(c) => c,
		Err(_) => {
			error!("Failed to read configuration file.");
			return;
		},
	};

	match Cli::parse().mode {
		Mode::Attest(attest_data) => {
			let attestation = match attest_data.to_attestation(&config) {
				Ok(a) => a,
				Err(e) => {
					error!("Error while creating attestation: {:?}", e);
					return;
				},
			};

			info!("Attesting...\n{:#?}", attestation);

			let client = Client::new(config);
			if let Err(e) = client.attest(attestation).await {
				error!("Error while attesting: {:?}", e);
			}
		},
		Mode::Attestations => match handle_attestations(config).await {
			Ok(_) => (),
			Err(e) => error!("Failed to execute attestations command: {:?}", e),
		},
		Mode::Bandada(bandada_data) => match handle_bandada(&config, bandada_data).await {
			Ok(_) => (),
			Err(e) => error!("Failed to execute bandada command: {:?}", e),
		},
		Mode::Compile => {
			info!("Compiling contracts...");
			match compile_att_station() {
				Ok(_) => info!("AttestationStation Compilation successful"),
				Err(e) => error!("Error during AttestationStation compilation: {}", e),
			}
			info!("Done!");
		},
		Mode::Deploy => {
			info!("Deploying contracts...");
			let client = Client::new(config);

			let as_address = match deploy_as(client.get_signer()).await {
				Ok(a) => a,
				Err(e) => {
					error!("Failed to deploy AttestationStation: {:?}", e);
					return;
				},
			};
			info!("AttestationStation deployed at {:?}", as_address);

			let verifier_address = match deploy_verifier(client.get_signer()).await {
				Ok(a) => a,
				Err(e) => {
					error!("Failed to deploy EigenTrustVerifier: {:?}", e);
					return;
				},
			};

			info!("EigenTrustVerifier deployed at {:?}", verifier_address);
		},
		Mode::LocalScores => match handle_scores(config, AttestationsOrigin::Local).await {
			Ok(_) => info!("Scores calculated."),
			Err(e) => error!("LocalScores command failed: {}", e),
		},
		Mode::Proof => {
			info!("Not implemented yet.");
		},
		Mode::Scores => match handle_scores(config, AttestationsOrigin::Fetch).await {
			Ok(_) => info!("Scores calculated."),
			Err(e) => error!("Scores command failed: {}", e),
		},
		Mode::Show => info!("Client config:\n{:#?}", config),
		Mode::Update(update_data) => match handle_update(&mut config, update_data) {
			Ok(_) => info!("Client configuration updated."),
			Err(e) => error!("Failed to update client configuration: {}", e),
		},
		Mode::Verify => {
			let client = Client::new(config);

			if let Err(e) = client.verify().await {
				error!("Failed to verify the proof: {:?}", e);
				return;
			}

			info!("Proof verified.");
		},
	}
}
