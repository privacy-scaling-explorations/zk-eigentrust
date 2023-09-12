use eigentrust_zk::utils::{generate_params, write_params};
use halo2::halo2curves::bn256::Bn256;

fn main() {
	let k = 20;
	let params = generate_params::<Bn256>(k);
	write_params(&params);
}
