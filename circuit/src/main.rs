use eigen_trust_circuit::utils::{generate_params, write_params};
use halo2wrong::curves::bn256::Bn256;
use std::env::current_dir;

/// Generate params for the circuit.
fn main() {
	let k = 9;
	generate_params_and_write(k);
}

fn generate_params_and_write(k: u32) {
	let params = generate_params::<Bn256>(k);
	let current_path = current_dir().unwrap();
	let path = format!("{}/../data/params-{}.bin", current_path.display(), k);
	write_params(&params, &path);
}
