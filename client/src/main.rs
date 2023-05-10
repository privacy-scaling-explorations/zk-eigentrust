use clap::Parser;
use eigen_trust_circuit::utils::{read_bytes_data, read_json_data};
use eigen_trust_client::{
	cli::*,
	utils::{
		compile_sol_contract, compile_yul_contracts, deploy_as, deploy_et_wrapper, deploy_verifier,
	},
	Client, ClientConfig,
};

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
			println!("Creating attestation...\n{:#?}", attest_data);

			let attestation = match attest_data.to_attestation() {
				Ok(a) => a,
				Err(e) => {
					println!("Error while creating attestation: {:?}", e);
					return;
				},
			};

			println!("Attesting...\n{:?}", attestation);

			let client = Client::new(config.clone());
			if let Err(e) = client.attest(attestation).await {
				println!("Error while attesting: {:?}", e);
			}
		},
		Mode::Compile => {
			println!("Compiling contracts...");
			compile_sol_contract();
			compile_yul_contracts();
			println!("Finished compiling!");
		},
		Mode::Deploy => {
			println!("Deploying contracts...");

			let address = match deploy_as(&config.mnemonic, &config.node_url).await {
				Ok(a) => a,
				Err(e) => {
					eprintln!("Failed to deploy the AttestationStation contract: {:?}", e);
					return;
				},
			};
			println!("AttestationStation contract deployed. Address: {}", address);

			let et_contract = read_bytes_data("et_verifier");

			let address =
				match deploy_verifier(&config.mnemonic, &config.node_url, et_contract).await {
					Ok(a) => a,
					Err(e) => {
						eprintln!("Failed to deploy the EigenTrustVerifier contract: {:?}", e);
						return;
					},
				};

			let w_addr = match deploy_et_wrapper(&config.mnemonic, &config.node_url, address).await
			{
				Ok(a) => a,
				Err(e) => {
					eprintln!("Failed to deploy the EtVerifierWrapper contract: {:?}", e);
					return;
				},
			};
			println!("EtVerifierWrapper contract deployed. Address: {}", w_addr);
		},
		Mode::Proof => {
			println!("Calculating Proof...\n");
			let mut client = Client::new(config);
			if let Err(e) = client.calculate_proofs().await {
				eprintln!("Error calculating proofs: {:?}", e);
			}
		},
		Mode::Show => println!("Client config:\n{:#?}", config),
		Mode::Update(update_data) => match config_update(&mut config, update_data) {
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
