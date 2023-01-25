mod attestation_station;
mod compile;
mod deploy;
mod sign;
mod transaction;

use attestation_station::{AttestationData as AsData, AttestationStation};
use csv::Reader as CsvReader;
use deploy::{deploy, setup_client};
use eigen_trust_circuit::{
	calculate_message_hash,
	eddsa::native::{sign, SecretKey},
	halo2::halo2curves::{bn256::Fr as Scalar, FieldExt},
	utils::to_short,
};
use eigen_trust_protocol::manager::{
	attestation::{Attestation, AttestationData},
	NUM_NEIGHBOURS,
};
use ethers::{
	abi::Address,
	prelude::k256::elliptic_curve::PrimeField,
	providers::{Middleware, StreamExt},
	solc::utils::read_json_file,
	types::Bytes,
};
use serde::{de::DeserializeOwned, Deserialize};
use std::{io::Error, path::Path, str::FromStr};

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

#[derive(Deserialize)]
struct InputData {
	ops: [u128; NUM_NEIGHBOURS],
	secret_key: [String; 2],
}

#[tokio::main]
async fn main() {
	let as_address = deploy().await.unwrap();
	let root = Path::new(&env!("CARGO_MANIFEST_DIR"));
	let boostrap_path = root.join("../data/bootstrap-nodes.csv");
	let input_path = root.join("../data/input-data.json");
	let user_secrets_raw: Vec<[String; 2]> = read_csv_file(boostrap_path).unwrap();
	let input_data: InputData = read_json_file(input_path).unwrap();
	assert!(user_secrets_raw.contains(&input_data.secret_key));

	let user_secrets_vec: Vec<SecretKey> = user_secrets_raw
		.into_iter()
		.map(|x| {
			let sk0_decoded = bs58::decode(&x[0]).into_vec().unwrap();
			let sk1_decoded = bs58::decode(&x[1]).into_vec().unwrap();
			let sk0 = to_short(&sk0_decoded);
			let sk1 = to_short(&sk1_decoded);
			SecretKey::from_raw([sk0, sk1])
		})
		.collect();

	let user_secrets: [SecretKey; NUM_NEIGHBOURS] = user_secrets_vec.try_into().unwrap();
	let user_publics = user_secrets.map(|s| s.public());

	let sk0_bytes = bs58::decode(&input_data.secret_key[0]).into_vec().unwrap();
	let sk1_bytes = bs58::decode(&input_data.secret_key[1]).into_vec().unwrap();

	let mut sk0: [u8; 32] = [0; 32];
	sk0[..].copy_from_slice(&sk0_bytes);

	let mut sk1: [u8; 32] = [0; 32];
	sk1[..].copy_from_slice(&sk1_bytes);

	let sk = SecretKey::from_raw([sk0, sk1]);
	let pk = sk.public();

	let ops = input_data.ops.map(|x| Scalar::from_u128(x));

	let (pks_hash, message_hash) =
		calculate_message_hash::<NUM_NEIGHBOURS, 1>(user_publics.to_vec(), vec![ops.to_vec()]);

	let sig = sign(&sk, &pk, message_hash[0]);

	let att = Attestation::new(sig, pk, user_publics.to_vec(), ops.to_vec());
	let att_data = AttestationData::from(att);
	let bytes = att_data.to_bytes();

	let client = setup_client();
	let main_address = client.get_accounts().await.unwrap()[0];
	let as_contract = AttestationStation::new(as_address, client);

	let as_data = AsData(
		Address::zero(),
		pks_hash.to_bytes(),
		Bytes::from(bytes.clone()),
	);
	let as_data_vec = vec![as_data];

	let _res = as_contract.attest(as_data_vec).send().await.unwrap().await.unwrap();

	let events = as_contract.events().query().await.unwrap();
	for event in events {
		let bytes = event.val.to_vec();
		let as_data = AttestationData::from_bytes(bytes);
		let as_obj = Attestation::from(as_data);

		let (as_pks_hash, _) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(as_obj.neighbours, vec![as_obj.scores]);

		assert!(as_pks_hash == pks_hash);
	}

	// Part 2
	// Collect all the attestations given the list of addresses that posted them
	// Turn these attestations into Attestation struct - validate them
	// Turn the attestations into AttestationData
	// Sumbit the into eigen-trust-server
}
