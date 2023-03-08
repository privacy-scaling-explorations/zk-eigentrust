use eigen_trust_circuit::{
	circuit::EigenTrust,
	utils::{generate_params, read_params, write_bytes_data, write_params},
	verifier::{gen_evm_verifier, gen_pk},
};
use halo2::halo2curves::bn256::Bn256;
use rand::thread_rng;

/// Generate params for the circuit.
fn main() {
	for k in 9..18 {
		generate_params_and_write(k);
	}
	// generate_et_verifier();
}

fn generate_params_and_write(k: u32) {
	let params = generate_params::<Bn256>(k);
	write_params(&params);
}

pub fn generate_et_verifier() {
	let rng = &mut thread_rng();

	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;
	let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(rng);

	let k = 14;
	let params = read_params(k);
	let pk = gen_pk(&params, &et);
	let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
	write_bytes_data(deployment_code, "et_verifier").unwrap();
}
