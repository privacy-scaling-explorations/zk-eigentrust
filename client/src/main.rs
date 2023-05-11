use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::utils::{read_bytes_data, read_json_data, write_json_data};
use eigen_trust_client::{
	utils::{
		compile_sol_contract, compile_yul_contracts, deploy_as, deploy_et_wrapper, deploy_verifier,
		PARTICIPANTS,
	},
	Client, ClientConfig,
};
use ethers::{
	abi::Address,
	providers::Http,
	signers::coins_bip39::{English, Mnemonic},
};
use std::str::FromStr;

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
}

impl Config {
	fn from_str(str: &str) -> Result<Config, &'static str> {
		match str {
			"as_address" => Ok(Config::AttestationStationAddress),
			"mnemonic" => Ok(Config::Mnemonic),
			"score" => Ok(Config::Score),
			"node_url" => Ok(Config::NodeUrl),
			_ => Err("Invalid config field"),
		}
	}
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let mut config: ClientConfig = read_json_data("client-config").expect("Failed to read config");

	match cli.mode {
		Mode::Attest => {
			let client = Client::new(config.clone());
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
			let mut client = Client::new(config);
			if let Err(e) = client.calculate_proofs().await {
				eprintln!("Error calculating proofs: {:?}", e);
			}
		},
		Mode::Show => println!("Client config:\n{:#?}", config),
		Mode::Update(data) => match config_update(&mut config, data) {
			Ok(_) => println!("Client configuration updated."),
			Err(e) => eprintln!("Failed to update client configuration.\n{}", e),
		},
		Mode::Verify => {
			let client = Client::new(config);

			if let Err(e) = client.verify().await {
				eprintln!("Failed to verify the proof: {:?}", e);
				return;
			}

			println!("Proof verified");
		},
	}
}

fn config_update(config: &mut ClientConfig, data: UpdateData) -> Result<(), String> {
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

			let score_parsed: Result<u8, _> = score.parse();
			if score_parsed.is_err() {
				return Err("Failed to parse score.".to_string());
			}

			let pos = PARTICIPANTS.iter().position(|x| &name == x);

			if pos.is_none() {
				return Err(format!(
					"Invalid neighbour name: {:?}, available: {:?}",
					name, PARTICIPANTS
				));
			}

			let pos = pos.unwrap();

			config.ops[pos] = score_parsed.unwrap();
		},
	}

	match write_json_data(config, "client-config") {
		Ok(_) => Ok(()),
		Err(e) => Err(e.to_string()),
	}
}
