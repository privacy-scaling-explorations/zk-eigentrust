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
	let user_secrets_raw: Vec<[String; 3]> = read_csv_data("bootstrap-nodes").unwrap();
	let config: ClientConfig = read_json_data("client-config").unwrap();

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
				eprintln!("Failed to deploy the AttestationStation contract: {:?}", e);
				return;
			}
			let address = deploy_res.unwrap();
			println!("AttestationStation contract deployed. Address: {}", address);

			let et_contract = read_bytes_data("et_verifier");
			let deploy_res =
				deploy_verifier(&config.mnemonic, &config.ethereum_node_url, et_contract).await;
			if let Err(e) = deploy_res {
				eprintln!("Failed to deploy the EigenTrustVerifier contract: {:?}", e);
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
			write_json_data(proof_raw.clone(), "et_proof").unwrap();
			let client = EigenTrustClient::new(config, user_secrets_raw);
			client.verify(proof_raw).await.unwrap();
			println!("Successful verification!");
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

			let res = write_json_data(client_config_updated, "client-config");
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
