use csv::Reader as CsvReader;
use ethers::{
	abi::Address,
	middleware::SignerMiddleware,
	prelude::{abigen, Abigen, ContractError},
	providers::{Http, Middleware, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	solc::Solc,
	types::TransactionRequest,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
	env,
	fs::{write, File},
	io::{BufReader, Error, Read},
	path::Path,
	sync::Arc,
};

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Vec<T>, Error> {
	let path = path.as_ref();
	let file = File::open(path)?;
	let file = BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}

/// Reads raw bytes from the file
pub fn read_bytes(path: impl AsRef<Path>) -> Vec<u8> {
	let f = File::open(path).unwrap();
	let mut reader = BufReader::new(f);
	let mut buffer = Vec::new();

	// Read file into vector.
	reader.read_to_end(&mut buffer).unwrap();

	buffer
}

/// Reads the json file and deserialize it into the provided type
pub fn write_json_file<T: Serialize>(json: T, path: impl AsRef<Path>) -> Result<(), Error> {
	let bytes = serde_json::to_vec(&json)?;
	write(path, bytes)?;
	Ok(())
}

abigen!(AttestationStation, "../contracts/AttestationStation.json");
pub type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;
pub type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub fn setup_client(mnemonic_phrase: &str, node_url: &str) -> SignerMiddlewareArc {
	let provider = Provider::<Http>::try_from(node_url).unwrap();
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic_phrase).build().unwrap();
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}

pub async fn deploy_as(mnemonic_phrase: &str, node_url: &str) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = AttestationStation::deploy(client, ())?.send().await?;
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub async fn deploy_et_verifier(
	mnemonic_phrase: &str, node_url: &str,
) -> Result<Address, CntrError> {
	let curr_dir = env::current_dir().unwrap();
	println!("{:?}", curr_dir);
	let contracts_dir = curr_dir.join("../data/et_verifier.bin");
	println!("{:?}", contracts_dir);
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = read_bytes(contracts_dir);
	let tx = TransactionRequest::default().data(contract);
	let pen_tx = client.send_transaction(tx, None).await.unwrap();
	let tx = pen_tx.await;

	let res = tx.unwrap();
	let rec = res.unwrap();
	Ok(rec.contract_address.unwrap())
}

pub fn compile() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../contracts/");
	println!("{:?}", contracts_dir);

	// compile it
	let contracts = Solc::default().compile_source(&contracts_dir).unwrap();
	let att_path = contracts_dir.join("AttestationStation.sol");
	let att_path_str = att_path.to_str().unwrap();
	let contract_name = "AttestationStation";
	let contract = contracts.get(att_path_str, contract_name).unwrap();
	let abi = contract.abi.unwrap();
	let abi_json = serde_json::to_string(abi).unwrap();
	let contract_json = serde_json::to_string(&contract).unwrap();

	let bindings = Abigen::new(&contract_name, abi_json.clone()).unwrap().generate().unwrap();

	// print to stdout if no output arg is given
	let bindings_dest = contracts_dir.join("AttestationStation.rs");
	let cntr_dest = contracts_dir.join("AttestationStation.json");

	bindings.write_to_file(bindings_dest).unwrap();
	write(cntr_dest, contract_json).unwrap();
}

#[cfg(test)]
mod test {
	use crate::utils::{deploy_as, deploy_et_verifier};
	use ethers::utils::Anvil;

	#[tokio::test]
	async fn should_deploy_the_as_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let res = deploy_as(mnemonic, &node_endpoint).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn should_deploy_the_et_verifier_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let res = deploy_et_verifier(mnemonic, &node_endpoint).await;
		assert!(res.is_ok());

		drop(anvil);
	}
}
