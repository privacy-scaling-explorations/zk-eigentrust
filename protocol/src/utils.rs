use eigen_trust_circuit::halo2wrong::curves::{bn256::Fr as Scalar, FieldExt};
use futures::{
	stream::{self, BoxStream, Fuse},
	StreamExt,
};
use rand::RngCore;
use tokio::time::{self, Duration, Instant};

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

pub fn scalar_from_bs58(key: &str) -> Scalar {
	let bytes = &bs58::decode(key).into_vec().unwrap();
	Scalar::from_bytes_wide(&to_wide_bytes(bytes))
}
