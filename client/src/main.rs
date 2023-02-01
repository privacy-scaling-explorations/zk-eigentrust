use clap::{Args, Parser, Subcommand};
use csv::Reader as CsvReader;
use eigen_trust_client::{
	utils::{compile, deploy},
	ClientConfig, EigenTrustClient,
};
use ethers::{
	abi::Address,
	providers::Http,
	signers::coins_bip39::{English, Mnemonic},
	solc::utils::read_json_file,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{env, fs, io::Error, path::Path, str::FromStr};

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Vec<T>, Error> {
	let path = path.as_ref();
	let file = std::fs::File::open(path)?;
	let file = std::io::BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}

/// Reads the json file and deserialize it into the provided type
pub fn write_json_file<T: Serialize>(json: T, path: impl AsRef<Path>) -> Result<(), Error> {
	let bytes = serde_json::to_vec(&json)?;
	fs::write(path, bytes)?;
	Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
	#[command(subcommand)]
	mode: Mode,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Subcommand)]
enum Mode {
	Show,
	Compile,
	Deploy,
	Attest,
	Update(UpdateData),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Args)]
struct UpdateData {
	name: Option<String>,
	score: Option<u128>,
	sk: Option<String>,
	as_address: Option<String>,
	mnemonic: Option<String>,
	node_url: Option<String>,
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();

	let root = env::current_dir().unwrap();
	let boostrap_path = root.join("../data/bootstrap-nodes.csv");
	let config_path = root.join("../data/client-config.json");
	let user_secrets_raw: Vec<[String; 3]> = read_csv_file(boostrap_path).unwrap();
	let config: ClientConfig = read_json_file(config_path.clone()).unwrap();

	let pos = user_secrets_raw.iter().position(|x| &config.secret_key == &x[1..]);
	assert!(pos.is_some());

	match cli.mode {
		Mode::Compile => {
			compile();
			println!("Finished compiling!");
		},
		Mode::Deploy => {
			let deploy_res = deploy(&config.mnemonic, &config.ethereum_node_url).await;
			if let Err(e) = deploy_res {
				eprintln!("Failed to deploy the AttestationStation contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			println!("AttestationStation contract deployed. Address: {}", address);
		},
		Mode::Attest => {
			let client = EigenTrustClient::new(config, user_secrets_raw);
			client.attest().await.unwrap();
		},
		Mode::Update(data) => {
			let UpdateData { name, score, sk, as_address, mnemonic, node_url } = data;

			let mut client_config_updated = config.clone();

			if let (Some(name), Some(score)) = (name, score) {
				let available_names: Vec<String> =
					user_secrets_raw.iter().map(|x| x[0].clone()).collect();
				let pos = available_names.iter().position(|x| &name == x);
				if pos.is_none() {
					eprintln!(
						"Invalid neighbour name: {:?}, available: {:?}",
						name, available_names
					);
					return;
				}
				let pos = pos.unwrap();
				client_config_updated.ops[pos] = score;
			} else {
				eprintln!("Please provice both name and score in order to update your opinion!");
			}

			if let Some(sk) = sk {
				let sk_vec: Vec<String> = sk.split(",").map(|x| x.to_string()).collect();
				if sk_vec.len() != 2 {
					eprintln!(
						"Invalid secret key passed, expected 2 bs58 values separated by commas, e.g.: \
						'2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67,9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF'"
					);
					return;
				}
				let sk: [String; 2] = sk_vec.try_into().unwrap();

				let sk0_decoded = bs58::decode(&sk[0]).into_vec();
				let sk1_decoded = bs58::decode(&sk[1]).into_vec();
				if sk0_decoded.is_err() || sk1_decoded.is_err() {
					eprintln!("Failed to decode secret key! Expecting bs58 encoded values!");
					return;
				}

				client_config_updated.secret_key = sk;
			}

			if let Some(as_address) = as_address {
				let as_address_parsed: Result<Address, _> = as_address.parse();
				if as_address_parsed.is_err() {
					eprintln!("Failed to parse address!");
					return;
				}

				client_config_updated.as_address = as_address;
			}

			if let Some(mnemonic) = mnemonic {
				let parsed_mnemonic = Mnemonic::<English>::new_from_phrase(&mnemonic);
				if parsed_mnemonic.is_err() {
					eprintln!("Failed to parse mnemonic!");
					return;
				}
				client_config_updated.mnemonic = mnemonic;
			}

			if let Some(node_url) = node_url {
				let provider = Http::from_str(&node_url);
				if provider.is_err() {
					eprintln!("Failed to parse node url!");
					return;
				}
				client_config_updated.ethereum_node_url = node_url;
			}

			let res = write_json_file(client_config_updated, config_path);
			if res.is_err() {
				println!("Failed to same updated config!");
			}
		},
		Mode::Show => {
			println!("Client config:");
			println!("{:#?}", config);
		},
	}
}
