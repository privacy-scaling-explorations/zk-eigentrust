mod bandada;
mod cli;

use clap::Parser;
use cli::*;
use eigen_trust_circuit::utils::{read_bytes_data, read_json_data};
use eigen_trust_client::{
	eth::{compile_sol_contract, compile_yul_contracts, deploy_as, deploy_verifier},
	storage::{CSVFileStorage, ScoreRecord, Storage},
	Client, ClientConfig,
};
use std::env::current_dir;

#[tokio::main]
async fn main() {
	let mut config: ClientConfig = match read_json_data("client-config") {
		Ok(c) => c,
		Err(_) => {
			eprintln!("Failed to read configuration file.");
			return;
		},
	};

	match Cli::parse().mode {
		Mode::Attest(attest_data) => {
			let attestation = match attest_data.to_attestation(&config) {
				Ok(a) => a,
				Err(e) => {
					eprintln!("Error while creating attestation: {:?}", e);
					return;
				},
			};

			println!("Attesting...\n{:#?}", attestation);

			let client = Client::new(config);
			if let Err(e) = client.attest(attestation).await {
				eprintln!("Error while attesting: {:?}", e);
			}
		},
		Mode::Bandada(bandada_data) => match handle_bandada(&config, bandada_data).await {
			Ok(_) => (),
			Err(e) => eprintln!("Failed to execute bandada command: {:?}", e),
		},
		Mode::Compile => {
			println!("Compiling contracts...");
			compile_sol_contract();
			compile_yul_contracts();
			println!("Done!");
		},
		Mode::Deploy => {
			println!("Deploying contracts...");
			let client = Client::new(config);

			let as_address = match deploy_as(client.get_signer()).await {
				Ok(a) => a,
				Err(e) => {
					eprintln!("Failed to deploy AttestationStation: {:?}", e);
					return;
				},
			};
			println!("AttestationStation deployed at {:?}", as_address);

			let verifier_contract = read_bytes_data("et_verifier");

			let verifier_address =
				match deploy_verifier(client.get_signer(), verifier_contract).await {
					Ok(a) => a,
					Err(e) => {
						eprintln!("Failed to deploy EigenTrustVerifier: {:?}", e);
						return;
					},
				};

			println!("EigenTrustVerifier deployed at {:?}", verifier_address);
		},
		Mode::Proof => {
			println!("Not implemented yet.");
		},
		Mode::Scores => {
			println!("Calculating scores...");
			let client = Client::new(config);

			if let Ok(scores) = client.calculate_scores().await {
				let score_records: Vec<ScoreRecord> =
					scores.into_iter().map(ScoreRecord::from_score).collect();
				let filepath = current_dir().unwrap().join("../data/scores.csv");
				let mut storage = CSVFileStorage::<ScoreRecord>::new(filepath);

				match storage.save(score_records) {
					Ok(_) => println!("Scores successfully saved to 'scores.csv'."),
					Err(e) => eprintln!("Failed to save score records: {:?}", e),
				}
			} else {
				eprintln!("Score calculation failed");
			}
		},
		Mode::Show => println!("Client config:\n{:#?}", config),
		Mode::Update(update_data) => match handle_update(&mut config, update_data) {
			Ok(_) => println!("Client configuration updated."),
			Err(e) => eprintln!("Failed to update client configuration: {}", e),
		},
		Mode::Verify => {
			let client = Client::new(config);

			if let Err(e) = client.verify().await {
				eprintln!("Failed to verify the proof: {:?}", e);
				return;
			}

			println!("Proof verified.");
		},
	}
}
