use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::{
	utils::{read_bytes_data, read_json_data, write_json_data},
	ProofRaw,
};
use eigen_trust_client::{
	utils::{
		compile_sol_contract, compile_yul_contracts, deploy_as, deploy_et_wrapper, deploy_verifier,
		read_csv_data,
	},
	ClientConfig, EigenTrustClient,
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
	Show,
	CompileContracts,
	DeployContracts,
	Attest,
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
	fn from_str(str: String) -> Result<Config, &'static str> {
		match str.as_str() {
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
	let user_secrets_raw: Vec<[String; 3]> = read_csv_data("bootstrap-nodes").unwrap();
	let mut config: ClientConfig = read_json_data("client-config").unwrap();

	let pos = user_secrets_raw.iter().position(|x| &config.secret_key == &x[1..]);
	assert!(pos.is_some());

	match cli.mode {
		Mode::CompileContracts => {
			compile_sol_contract();
			compile_yul_contracts();
			println!("Finished compiling!");
		},
		Mode::DeployContracts => {
			let deploy_res = deploy_as(&config.mnemonic, &config.ethereum_node_url).await;
			if let Err(e) = deploy_res {
				println!("Failed to deploy the AttestationStation contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			println!("AttestationStation contract deployed. Address: {}", address);

			let et_contract = read_bytes_data("et_verifier");
			let deploy_res =
				deploy_verifier(&config.mnemonic, &config.ethereum_node_url, et_contract).await;
			if let Err(e) = deploy_res {
				println!("Failed to deploy the EigenTrustVerifier contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			let wrapper_res =
				deploy_et_wrapper(&config.mnemonic, &config.ethereum_node_url, address).await;
			let w_addr = wrapper_res.unwrap();
			println!("EtVerifierWrapper contract deployed. Address: {}", w_addr);
		},
		Mode::Attest => {
			let client = EigenTrustClient::new(config, user_secrets_raw);
			client.attest().await.unwrap();
		},
		Mode::Verify => {
			let url = format!("{}/score", config.server_url);
			let proof_raw: ProofRaw = reqwest::get(url).await.unwrap().json().await.unwrap();
			let client = EigenTrustClient::new(config, user_secrets_raw);
			client.verify(proof_raw).await.unwrap();
			println!("Successful verification!");
		},
		Mode::Update(data) => {
			let UpdateData { field, new_data } = data;

			if let Some(f) = field {
				if let Ok(config_field) = Config::from_str(f) {
					match config_field {
						Config::AttestationStationAddress => {
							if let Some(new_data) = new_data {
								let as_address_parsed: Result<Address, _> = new_data.parse();

								if as_address_parsed.is_err() {
									println!("Failed to parse address");
									return;
								}

								config.as_address = new_data;
							} else {
								println!("Please provide a new address");
							}
						},
						Config::Mnemonic => {
							if let Some(new_data) = new_data {
								let parsed_mnemonic =
									Mnemonic::<English>::new_from_phrase(&new_data);

								if parsed_mnemonic.is_err() {
									println!("Failed to parse mnemonic!");
									return;
								}

								config.mnemonic = new_data;
							} else {
								println!("Please provide a new mnemonic");
							}
						},
						Config::NodeUrl => {
							if let Some(new_data) = new_data {
								let provider = Http::from_str(&new_data);

								if provider.is_err() {
									println!("Failed to parse node url!");
									return;
								}

								config.ethereum_node_url = new_data;
							} else {
								println!("Please provide a new node url");
							}
						},
						Config::Score => {
							if let Some(new_data) = new_data {
								let input: Vec<String> =
									new_data.split(" ").map(|x| x.to_string()).collect();

								if input.len() != 2 {
									println!("Invalid input format. Expected: \"Alice 100\"");
									return;
								}

								let name = input[0].clone();
								let score = input[1].clone();

								let score_parsed: Result<u128, _> = score.parse();
								if score_parsed.is_err() {
									println!("Failed to parse score");
									return;
								}

								let available_names: Vec<String> =
									user_secrets_raw.iter().map(|x| x[0].clone()).collect();
								let pos = available_names.iter().position(|x| &name == x);

								if pos.is_none() {
									println!(
										"Invalid neighbour name: {:?}, available: {:?}",
										name, available_names
									);
									return;
								}

								let pos = pos.unwrap();
								config.ops[pos] = score_parsed.unwrap();
							} else {
								println!(
									"Please provice both name and score in order to update your opinion");
							}
						},
						Config::SecretKey => {
							if let Some(new_data) = new_data {
								let sk_vec: Vec<String> =
									new_data.split(",").map(|x| x.to_string()).collect();
								if sk_vec.len() != 2 {
									println!(
										"Invalid secret key passed, expected 2 bs58 values separated by commas, e.g.: \
										'2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67,9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF'"
									);
									return;
								}

								let sk: [String; 2] = sk_vec.try_into().unwrap();
								let sk0_decoded = bs58::decode(&sk[0]).into_vec();
								let sk1_decoded = bs58::decode(&sk[1]).into_vec();

								if sk0_decoded.is_err() || sk1_decoded.is_err() {
									println!(
										"Failed to decode secret key! Expecting bs58 encoded values!"
									);
									return;
								}
							} else {
								println!("Please provide a new secret key");
							}
						},
					}
				} else {
					println!("Invalid field name");
				}
			} else {
				println!("Please provide a field to update!");
			}

			let res = write_json_data(config, "client-config");
			if res.is_err() {
				println!("Failed to update config");
			}
		},
		Mode::Show => {
			println!("Client config:\n{:#?}", config);
		},
	}
}
