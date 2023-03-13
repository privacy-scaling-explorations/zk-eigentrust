use eigen_trust_circuit::{
	circuit::{native, EigenTrust, PoseidonNativeHasher, PoseidonNativeSponge},
	eddsa::native::{sign, SecretKey, Signature},
	utils::{generate_params, read_params, write_json_data, write_params, write_yul_data},
	verifier::{gen_evm_verifier_code, gen_pk, gen_proof},
	Proof, ProofRaw,
};
use halo2::halo2curves::{
	bn256::{Bn256, Fr as Scalar},
	FieldExt,
};
use rand::thread_rng;
use std::env::current_dir;

/// Generate params for the circuit.
fn main() {
	generate_params_and_write();
	generate_et_verifier();
}

fn generate_params_and_write() {
	let curr_dir = current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");
	for k in 9..18 {
		let path = contracts_dir.join(format!("params-{}.bin", k));
		if path.exists() {
			continue;
		}
		let params = generate_params::<Bn256>(k);
		write_params(&params);
	}
}

pub fn generate_et_verifier() {
	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;
	let s = vec![Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
	let ops: Vec<Vec<Scalar>> = vec![
		vec![0, 200, 300, 500, 0],
		vec![100, 0, 100, 100, 700],
		vec![400, 100, 0, 200, 300],
		vec![100, 100, 700, 0, 100],
		vec![300, 100, 400, 200, 0],
	]
	.into_iter()
	.map(|arr| arr.into_iter().map(|x| Scalar::from_u128(x)).collect())
	.collect();
	let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops.clone());

	let rng = &mut thread_rng();
	let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
	let pub_keys = secret_keys.clone().map(|x| x.public());

	let pk_x = pub_keys.clone().map(|pk| pk.0.x);
	let pk_y = pub_keys.clone().map(|pk| pk.0.y);
	let mut sponge = PoseidonNativeSponge::new();
	sponge.update(&pk_x);
	sponge.update(&pk_y);
	let keys_message_hash = sponge.squeeze();

	let messages: Vec<Scalar> = ops
		.iter()
		.map(|scores| {
			let mut sponge = PoseidonNativeSponge::new();
			sponge.update(&scores);
			let scores_message_hash = sponge.squeeze();

			let m_inputs = [
				keys_message_hash,
				scores_message_hash,
				Scalar::zero(),
				Scalar::zero(),
				Scalar::zero(),
			];
			let poseidon = PoseidonNativeHasher::new(m_inputs);
			let res = poseidon.permute()[0];
			res
		})
		.collect();

	let signatures: Vec<Signature> = secret_keys
		.into_iter()
		.zip(pub_keys.clone())
		.zip(messages.clone())
		.map(|((sk, pk), msg)| sign(&sk, &pk, msg))
		.collect();

	let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
		pub_keys.to_vec(),
		signatures,
		ops,
		messages,
	);

	let k = 14;
	let params = read_params(k);
	let pk = gen_pk(&params, &et);
	let contract_code = gen_evm_verifier_code(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
	write_yul_data(contract_code, "et_verifier").unwrap();

	let proof_bytes = gen_proof(&params, &pk, et.clone(), vec![res.clone()]);
	let proof = Proof { pub_ins: res, proof: proof_bytes };
	let proof_raw: ProofRaw = proof.into();
	write_json_data(proof_raw, "et_proof").unwrap();
}
