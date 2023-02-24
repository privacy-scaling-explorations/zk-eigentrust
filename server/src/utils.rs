use eigen_trust_circuit::{
	eddsa::native::{PublicKey, SecretKey},
	halo2::halo2curves::{bn256::Fr as Scalar, FieldExt},
};

/// Write an array of 32 elements into an array of 64 elements.
pub fn to_wide(p: [u8; 32]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..32].copy_from_slice(&p[..]);
	res
}

/// Write a byte array into an array of 64 elements.
pub fn to_wide_bytes(p: &[u8]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..p.len()].copy_from_slice(p);
	res
}

/// Construct a Scalar value from bs58 string
pub fn scalar_from_bs58(key: &str) -> Scalar {
	let bytes = &bs58::decode(key).into_vec().unwrap();
	Scalar::from_bytes_wide(&to_wide_bytes(bytes))
}

/// Construct the secret keys and public keys from the given raw data
pub fn keyset_from_raw<const N: usize>(
	sks_raw: [[&str; 2]; N],
) -> (Vec<SecretKey>, Vec<PublicKey>) {
	let mut sks = Vec::new();
	let mut pks = Vec::new();
	for i in 0..N {
		let sk_raw = sks_raw[i];
		let sk0_raw = bs58::decode(sk_raw[0]).into_vec().unwrap();
		let sk1_raw = bs58::decode(sk_raw[1]).into_vec().unwrap();

		let mut sk0_bytes: [u8; 32] = [0; 32];
		sk0_bytes.copy_from_slice(&sk0_raw);
		let mut sk1_bytes: [u8; 32] = [0; 32];
		sk1_bytes.copy_from_slice(&sk1_raw);

		let sk = SecretKey::from_raw([sk0_bytes, sk1_bytes]);
		let pk = sk.public();

		sks.push(sk);
		pks.push(pk);
	}

	(sks, pks)
}
