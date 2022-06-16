mod utils;

use ecc::halo2::poly::commitment::Params;
use halo2wrong::curves::bn256::Bn256;
use std::env::current_dir;
use utils::{generate_params, write_params};

fn main() {
	let k = 18;
	let params = generate_params::<Bn256>(k);
	let current_path = current_dir().unwrap();
	let path = format!("{}/../data/params-18.bin", current_path.display());
	write_params(&params, &path);
}
