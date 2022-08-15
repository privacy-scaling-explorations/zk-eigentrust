use halo2wrong::curves::bn256::Fr;
use num_bigint::BigUint;
use halo2curves::bn256::Fr as ForkFr;

pub fn reduce(f: Fr) -> Fr {
	let suborder = BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373040",
        10,
    ).unwrap();
	let big_f = BigUint::from_bytes_le(&f.to_bytes());
	let big_f_reduced = big_f % suborder;

	let mut bytes: [u8; 32] = [0; 32];
	bytes.copy_from_slice(&big_f_reduced.to_bytes_le()[..]);
	Fr::from_bytes(&bytes).unwrap()
}

pub fn mont_reduce(f: Fr) -> Fr {
	let bytes = f.to_bytes();
	let fork_f: ForkFr = ForkFr::from_bytes(&bytes).unwrap();
	let reduced_f = fork_f.reduce();
	let new_bytes = reduced_f.to_bytes();
	Fr::from_bytes(&new_bytes).unwrap()
}