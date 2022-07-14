use crate::EigenError;
use eigen_trust_circuit::{
	ecdsa::Keypair,
	halo2wrong::{
		utils::decompose,
		curves::{
			bn256::Fr as Bn256Scalar,
			group::Curve,
			secp256k1::{Fp as Secp256k1Base, Fq as Secp256k1Scalar, Secp256k1Affine},
			CurveAffine, FieldExt,
		},
	},
};
use libp2p::core::{identity::Keypair as IdentityKeypair, PublicKey as IdentityPublicKey};
use super::opinion::Posedion5x5;

/// Convert the libp2p keypair into halo2 keypair.
pub fn convert_keypair(kp: &IdentityKeypair) -> Result<Keypair<Secp256k1Affine>, EigenError> {
	match kp {
		IdentityKeypair::Secp256k1(secp_kp) => {
			let mut sk_bytes = secp_kp.secret().to_bytes();
			sk_bytes.reverse();

			let sk_op: Option<Secp256k1Scalar> = Secp256k1Scalar::from_bytes(&sk_bytes).into();
			let sk = sk_op.ok_or(EigenError::InvalidKeypair)?;
			let g = Secp256k1Affine::generator();
			let pk = (g * sk).to_affine();

			Ok(Keypair::from_pair(sk, pk))
		},
		_ => Err(EigenError::InvalidKeypair),
	}
}

/// Convert the libp2p public key into halo2 public key.
pub fn convert_pubkey(pk: &IdentityPublicKey) -> Result<Secp256k1Affine, EigenError> {
	match pk {
		IdentityPublicKey::Secp256k1(secp_pk) => {
			let pk_bytes = secp_pk.encode_uncompressed();
			let mut x_bytes: [u8; 32] = pk_bytes[1..33]
				.try_into()
				.map_err(|_| EigenError::InvalidPubkey)?;
			let mut y_bytes: [u8; 32] = pk_bytes[33..65]
				.try_into()
				.map_err(|_| EigenError::InvalidPubkey)?;
			x_bytes.reverse();
			y_bytes.reverse();

			let x_op: Option<Secp256k1Base> = Secp256k1Base::from_bytes(&x_bytes).into();
			let y_op: Option<Secp256k1Base> = Secp256k1Base::from_bytes(&y_bytes).into();
			let x = x_op.ok_or(EigenError::InvalidPubkey)?;
			let y = y_op.ok_or(EigenError::InvalidPubkey)?;

			let pubkey_op: Option<Secp256k1Affine> = Secp256k1Affine::from_xy(x, y).into();
			let pubkey = pubkey_op.ok_or(EigenError::InvalidPubkey)?;
			Ok(pubkey)
		},
		_ => Err(EigenError::InvalidPubkey),
	}
}

pub fn extract_sk_limbs(kp: &IdentityKeypair) -> Result<[Bn256Scalar; 4], EigenError> {
	match kp {
		IdentityKeypair::Secp256k1(secp_kp) => {
			let mut sk_bytes = secp_kp.secret().to_bytes();
			sk_bytes.reverse();

			let sk_op: Option<Secp256k1Scalar> = Secp256k1Scalar::from_bytes(&sk_bytes).into();
			let sk = sk_op.ok_or(EigenError::InvalidKeypair)?;

			let limbs: Vec<Bn256Scalar> = decompose(sk, 4, 254).iter().map(|item| {
				let bytes = item.to_bytes();
				Bn256Scalar::from_bytes_wide(&to_wide(bytes))
			}).collect();

			assert!(limbs.len() == 4);

			Ok([limbs[0], limbs[1], limbs[2], limbs[3]])
		}
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