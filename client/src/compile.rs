use ethers::{prelude::Abigen, solc::Solc};
use std::{env, fs::write};

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
