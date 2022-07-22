use super::opinion::Posedion5x5;
use crate::EigenError;
use eigen_trust_circuit::halo2wrong::{
	curves::{bn256::Fr as Bn256Scalar, secp256k1::Fq as Secp256k1Scalar, FieldExt},
	utils::decompose,
};
use libp2p::core::identity::Keypair as IdentityKeypair;

pub fn extract_sk_limbs(kp: &IdentityKeypair) -> Result<[Bn256Scalar; 4], EigenError> {
	match kp {
		IdentityKeypair::Secp256k1(secp_kp) => {
			let mut sk_bytes = secp_kp.secret().to_bytes();
			sk_bytes.reverse();

			let sk_op: Option<Secp256k1Scalar> = Secp256k1Scalar::from_bytes(&sk_bytes).into();
			let sk = sk_op.ok_or(EigenError::InvalidKeypair)?;

			let limbs: Vec<Bn256Scalar> = decompose(sk, 4, 254)
				.iter()
				.map(|item| {
					let bytes = item.to_bytes();
					Bn256Scalar::from_bytes_wide(&to_wide(bytes))
				})
				.collect();

			assert!(limbs.len() == 4);

			Ok([limbs[0], limbs[1], limbs[2], limbs[3]])
		},
		_ => Err(EigenError::InvalidKeypair),
	}
}

pub fn extract_pub_key(kp: &IdentityKeypair) -> Result<Bn256Scalar, EigenError> {
	let limbs = extract_sk_limbs(kp)?;

	let input = [Bn256Scalar::zero(), limbs[0], limbs[1], limbs[2], limbs[3]];
	let pos = Posedion5x5::new(input);
	let out = pos.permute()[0];

	Ok(out)
}

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
