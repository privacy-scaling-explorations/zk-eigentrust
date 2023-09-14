use std::time::Instant;

use eigentrust_zk::utils::{generate_params, write_params};
use halo2::halo2curves::bn256::Bn256;

fn main() {
	let k = 20;
	let start = Instant::now();
	let params = generate_params::<Bn256>(k);
	let end = start.elapsed();
	println!("Params generation time: {:?}", end);
	write_params(&params);
}
