use eigen_trust_circuit::{
	circuit::EigenTrust,
	utils::{generate_params, write_bytes_data, write_params},
	verifier::{gen_evm_verifier, gen_pk, gen_srs},
};
use halo2::halo2curves::bn256::Bn256;
use rand::thread_rng;
use std::env::current_dir;

/// Generate params for the circuit.
fn main() {
	// let k = 9;
	// generate_params_and_write(k);
	generate_et_verifier();
}

fn generate_params_and_write(k: u32) {
	let params = generate_params::<Bn256>(k);
	let current_path = current_dir().unwrap();
	let path = format!("{}/../data/params-{}.bin", current_path.display(), k);
	write_params(&params, &path);
}

pub fn generate_et_verifier() {
	let rng = &mut thread_rng();

	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;
	let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(rng);

	let k = 14;
	let params = gen_srs(k);
	let pk = gen_pk(&params, &et);
	let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
	write_bytes_data(deployment_code, "et_verifier").unwrap();
}
