mod bandada;
mod cli;

use clap::Parser;
use cli::*;
use eigen_trust_client::{
	eth::{compile_att_station, compile_yul_contracts, deploy_as, deploy_verifier},
	fs::{get_file_path, read_binary, read_json, FileType},
	storage::{CSVFileStorage, ScoreRecord, Storage},
	Client, ClientConfig,
};

#[tokio::main]
async fn main() {
	let mut config: ClientConfig = match read_json("client-config") {
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
		Mode::Attestations => match handle_attestations(config).await {
			Ok(_) => (),
			Err(e) => eprintln!("Failed to execute attestations command: {:?}", e),
		},
		Mode::Bandada(bandada_data) => match handle_bandada(&config, bandada_data).await {
			Ok(_) => (),
			Err(e) => eprintln!("Failed to execute bandada command: {:?}", e),
		},
		Mode::Compile => {
			println!("Compiling contracts...");
			compile_att_station();
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

			let verifier_contract = read_binary("et_verifier").unwrap();

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
		Mode::LocalScores => match handle_scores(config, AttestationsOrigin::Local).await {
			Ok(_) => println!("Scores calculated."),
			Err(e) => eprintln!("LocalScores command failed: {}", e),
		},
		Mode::Proof => {
			println!("Not implemented yet.");
		},
		Mode::Scores => match handle_scores(config, AttestationsOrigin::Fetch).await {
			Ok(_) => println!("Scores calculated."),
			Err(e) => eprintln!("Scores command failed: {}", e),
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
