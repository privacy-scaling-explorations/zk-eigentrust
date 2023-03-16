use csv::Reader as CsvReader;
use eigen_trust_circuit::{
	halo2::halo2curves::bn256::Fr as Scalar,
	utils::{read_yul_data, write_bytes_data},
	verifier::{compile_yul, encode_calldata},
	Proof as NativeProof,
};
use ethers::{
	abi::Address,
	middleware::SignerMiddleware,
	prelude::{abigen, Abigen, ContractError},
	providers::{Http, Middleware, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	solc::{artifacts::ContractBytecode, Solc},
	types::TransactionRequest,
};
use serde::de::DeserializeOwned;
use std::{
	env,
	fs::{self, write, File},
	io::{BufReader, Error},
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

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_data<T: DeserializeOwned>(file_name: &str) -> Result<Vec<T>, Error> {
	let current_dir = env::current_dir().unwrap();
	let path = current_dir.join(format!("../data/{}.csv", file_name));
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

abigen!(AttestationStation, "../data/AttestationStation.json");
abigen!(EtVerifierWrapper, "../data/EtVerifierWrapper.json");
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

pub async fn deploy_et_wrapper(
	mnemonic_phrase: &str, node_url: &str, verifier_address: Address,
) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = EtVerifierWrapper::deploy(client, verifier_address)?.send().await?;
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub async fn deploy_verifier(
	mnemonic_phrase: &str, node_url: &str, contract_bytes: Vec<u8>,
) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let tx = TransactionRequest::default().data(contract_bytes);
	let pen_tx = client.send_transaction(tx, None).await.unwrap();
	let tx = pen_tx.await;

	let res = tx.unwrap();
	let rec = res.unwrap();
	let addr = rec.contract_address.unwrap();
	println!("Deployed contract address: {:?}", addr);
	Ok(addr)
}

pub async fn call_verifier(
	mnemonic_phrase: &str, node_url: &str, verifier_address: Address, proof: NativeProof,
) {
	let calldata = encode_calldata::<Scalar>(&[proof.pub_ins], &proof.proof);
	let client = setup_client(mnemonic_phrase, node_url);

	let tx = TransactionRequest::default().data(calldata).to(verifier_address);
	let pen_tx = client.send_transaction(tx, None).await.unwrap();

	let res = pen_tx.await.unwrap();
	println!("{:#?}", res);
}

pub fn compile_sol_contract() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");
	println!("{:?}", contracts_dir);

	// compile it
	let contracts = Solc::default().compile_source(&contracts_dir).unwrap();
	for (name, contr) in contracts.contracts_iter() {
		let bindings_path = contracts_dir.join(format!("{}.rs", name));
		let cntr_path = contracts_dir.join(format!("{}.json", name));
		println!("{:?}", name);
		let contract: ContractBytecode = contr.clone().into();
		let abi = contract.clone().abi.unwrap();
		let abi_json = serde_json::to_string(&abi).unwrap();
		let contract_json = serde_json::to_string(&contract).unwrap();
		let bindings = Abigen::new(&name, abi_json.clone()).unwrap().generate().unwrap();

		// write to /data folder
		bindings.write_to_file(bindings_path.clone()).unwrap();
		write(cntr_path.clone(), contract_json).unwrap();
	}
}

pub fn compile_yul_contracts() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");
	let paths = fs::read_dir(contracts_dir).unwrap();

	for path in paths {
		let path = path.unwrap().path();
		let name_with_suffix = path.file_name().unwrap().to_str().unwrap();
		if !name_with_suffix.ends_with(".yul") {
			continue;
		}
		let name = name_with_suffix.strip_suffix(".yul").unwrap();
		// // compile it
		let code = read_yul_data(&name);
		let compiled_contract = compile_yul(&code);
		write_bytes_data(compiled_contract, &name).unwrap();
	}
}

#[cfg(test)]
mod test {
	use super::{call_verifier, deploy_as, deploy_verifier};
	use eigen_trust_circuit::{
		utils::{read_bytes_data, read_json_data},
		Proof, ProofRaw,
	};
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
		let et_contract = read_bytes_data("et_verifier");
		let res = deploy_verifier(mnemonic, &node_endpoint, et_contract).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn should_call_et_verifier_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();

		let bytecode = read_bytes_data("et_verifier");
		let addr = deploy_verifier(mnemonic, &node_endpoint, bytecode).await.unwrap();

		let proof_raw: ProofRaw = read_json_data("et_proof").unwrap();
		let proof = Proof::from(proof_raw);
		call_verifier(mnemonic, &node_endpoint, addr, proof).await;

		drop(anvil);
	}
}
