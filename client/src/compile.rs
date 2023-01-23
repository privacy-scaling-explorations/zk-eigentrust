use ethers::{prelude::Abigen, solc::Solc};
use std::{fs::write, path::Path};

pub fn compile() {
	let contract_name = String::from("AttestationStation");
	let source = Path::new(&env!("CARGO_MANIFEST_DIR")).join("contracts/AttestationStation.sol");

	// compile it
	let contracts = Solc::default().compile_source(&source).unwrap();
	let contract = contracts.get(&source.to_str().unwrap(), &contract_name).unwrap();
	let abi = contract.abi.unwrap();
	let abi_json = serde_json::to_string(abi).unwrap();
	let contract_json = serde_json::to_string(&contract).unwrap();

	let bindings = Abigen::new(&contract_name, abi_json.clone()).unwrap().generate().unwrap();

	// print to stdout if no output arg is given
	let root = Path::new(&env!("CARGO_MANIFEST_DIR"));
	let bindings_dest = root.join("contracts/AttestationStation.rs");
	let cntr_dest = root.join("contracts/AttestationStation.json");

	bindings.write_to_file(bindings_dest).unwrap();
	write(cntr_dest, contract_json).unwrap();
}
