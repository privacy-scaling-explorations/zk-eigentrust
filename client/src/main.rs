use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::{
	utils::{read_bytes_data, read_json_data, write_json_data},
	ProofRaw,
};
use eigen_trust_client::{
	manager::{Manager, MANAGER_STORE},
	utils::{
		compile_sol_contract, compile_yul_contracts, deploy_as, deploy_et_wrapper, deploy_verifier,
		ecdsa_wallets_from_mnemonic, eddsa_key_pairs_from_mnemonic, get_attestations,
		read_csv_data,
	},
	Client, ClientConfig,
};
use ethers::{
	abi::Address,
	providers::Http,
	signers::coins_bip39::{English, Mnemonic},
};
use std::{str::FromStr, sync::Arc};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
	#[command(subcommand)]
	mode: Mode,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Subcommand)]
enum Mode {
	Attest,
	CompileContracts,
	DeployContracts,
	GenerateProof,
	Show,
	Update(UpdateData),
	Verify,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Args)]
struct UpdateData {
	field: Option<String>,
	new_data: Option<String>,
}

enum Config {
	AttestationStationAddress,
	Mnemonic,
	NodeUrl,
	Score,
	SecretKey,
}

impl Config {
	fn from_str(str: &str) -> Result<Config, &'static str> {
		match str {
			"as_address" => Ok(Config::AttestationStationAddress),
			"mnemonic" => Ok(Config::Mnemonic),
			"score" => Ok(Config::Score),
			"node_url" => Ok(Config::NodeUrl),
			"sk" => Ok(Config::SecretKey),
			_ => Err("Invalid config field"),
		}
	}
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let user_secrets_raw: Vec<[String; 3]> =
		read_csv_data("bootstrap-nodes").expect("Failed to read bootstrap nodes");
	let mut config: ClientConfig = read_json_data("client-config").expect("Failed to read config");
	let mng_store = Arc::clone(&MANAGER_STORE);

	user_secrets_raw
		.iter()
		.position(|x| config.secret_key == x[1..])
		.expect("No user found with the given secret key");

	// Create ethereum wallets
	// let wallets = ecdsa_wallets_from_mnemonic(&config.mnemonic, 5);

	let eddsa_pairs = eddsa_key_pairs_from_mnemonic(&config.mnemonic, 5);

	println!("EEDSA pairs:\n{:#?}", eddsa_pairs);

	// Generate EDDSA private keys
	// let mut sks = Vec::new();

	match cli.mode {
		Mode::Attest => {
			let client = Client::new(config.clone(), user_secrets_raw);
			println!("Attestations:\n{:#?}", config.ops);
			client.attest().await.unwrap();
		},
		Mode::CompileContracts => {
			compile_sol_contract();
			compile_yul_contracts();
			println!("Finished compiling!");
		},
		Mode::DeployContracts => {
			let deploy_res = deploy_as(&config.mnemonic, &config.node_url).await;
			if let Err(e) = deploy_res {
				eprintln!("Failed to deploy the AttestationStation contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			println!("AttestationStation contract deployed. Address: {}", address);

			let et_contract = read_bytes_data("et_verifier");
			let deploy_res = deploy_verifier(&config.mnemonic, &config.node_url, et_contract).await;
			if let Err(e) = deploy_res {
				eprintln!("Failed to deploy the EigenTrustVerifier contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			let wrapper_res = deploy_et_wrapper(&config.mnemonic, &config.node_url, address).await;
			let w_addr = wrapper_res.unwrap();
			println!("EtVerifierWrapper contract deployed. Address: {}", w_addr);
		},
		Mode::GenerateProof => {
			let attestations = match get_attestations(&config).await {
				Ok(attestations) => attestations,
				Err(e) => {
					eprintln!("Failed to get attestations: {:?}", e);
					return;
				},
			};

			let mut manager = match mng_store.lock() {
				Ok(manager) => manager,
				Err(_) => {
					eprintln!("Failed to lock manager store");
					return;
				},
			};

			manager.generate_initial_attestations();

			if let Err(e) = manager.add_attestations(attestations) {
				eprintln!("Error adding attestations: {:?}", e);
				return;
			}

			if let Err(e) = manager.calculate_proofs() {
				eprintln!("Error calculating proofs: {:?}", e);
			}
		},
		Mode::Show => println!("Client config:\n{:#?}", config),
		Mode::Update(data) => match config_update(&mut config, data, user_secrets_raw) {
			Ok(_) => println!("Client configuration updated."),
			Err(e) => eprintln!("Failed to update client configuration.\n{}", e),
		},
		Mode::Verify => {
			let client = Client::new(config, user_secrets_raw);

			let last_proof = match Manager::get_last_proof() {
				Ok(proof) => ProofRaw::from(proof),
				Err(e) => {
					eprintln!("Failed to get the last proof: {:?}", e);
					return;
				},
			};

			if let Err(e) = client.verify(last_proof).await {
				eprintln!("Failed to verify the proof: {:?}", e);
				return;
			}

			println!("Proof verified");
		},
	}
}

fn config_update(
	config: &mut ClientConfig, data: UpdateData, user_secrets_raw: Vec<[String; 3]>,
) -> Result<(), String> {
	let UpdateData { field, new_data } = data;

	if field.is_none() {
		return Err("Please provide a field to update.".to_string());
	}

	if new_data.is_none() {
		return Err("Please provide the update data, e.g. update score \"Alice 100\"".to_string());
	}

	let data = new_data.unwrap();

	match Config::from_str(&field.unwrap())? {
		Config::AttestationStationAddress => {
			let as_address_parsed: Result<Address, _> = data.parse();

			match as_address_parsed {
				Ok(_) => config.as_address = data,
				Err(_) => return Err("Failed to parse address.".to_string()),
			}
		},
		Config::Mnemonic => match Mnemonic::<English>::new_from_phrase(&data) {
			Ok(_) => config.mnemonic = data,
			Err(_) => return Err("Failed to parse mnemonic.".to_string()),
		},
		Config::NodeUrl => match Http::from_str(&data) {
			Ok(_) => config.node_url = data,
			Err(_) => return Err("Failed to parse node url.".to_string()),
		},
		Config::Score => {
			let input: Vec<String> = data.split(' ').map(|x| x.to_string()).collect();

			if input.len() != 2 {
				return Err("Invalid input format. Expected: \"Alice 100\"".to_string());
			}

			let name = input[0].clone();
			let score = input[1].clone();

			let score_parsed: Result<u128, _> = score.parse();
			if score_parsed.is_err() {
				return Err("Failed to parse score.".to_string());
			}

			let available_names: Vec<String> =
				user_secrets_raw.iter().map(|x| x[0].clone()).collect();
			let pos = available_names.iter().position(|x| &name == x);

			if pos.is_none() {
				return Err(format!(
					"Invalid neighbour name: {:?}, available: {:?}",
					name, available_names
				));
			}

			let pos = pos.unwrap();

			config.ops[pos] = score_parsed.unwrap();
		},
		Config::SecretKey => {
			let sk_vec: Vec<String> = data.split(',').map(|x| x.to_string()).collect();
			if sk_vec.len() != 2 {
				return Err(
					"Invalid secret key passed, expected 2 bs58 values separated by commas, \
					 e.g.:\n\"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67,\
					 9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF\""
						.to_string(),
				);
			}

			let sk: [String; 2] = sk_vec.try_into().unwrap();
			let sk0_decoded = bs58::decode(&sk[0]).into_vec();
			let sk1_decoded = bs58::decode(&sk[1]).into_vec();

			if sk0_decoded.is_err() || sk1_decoded.is_err() {
				return Err(
					"Failed to decode secret key. Expecting bs58 encoded values.".to_string(),
				);
			}

			config.secret_key = sk;
		},
	}

	match write_json_data(config, "client-config") {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string()),
	}
}
