use crate::Epoch;
use eigen_trust_circuit::{
	ecdsa::native::{generate_signature, verify_signature, Keypair, SigData},
	halo2wrong::curves::{
		bn256::Fr as Bn256Scalar,
		group::Curve,
		secp256k1::{Fp as Secp256k1Base, Fq as Secp256k1Scalar, Secp256k1Affine},
		CurveAffine, FieldExt,
	},
	poseidon::{params::Params5x5Bn254, Poseidon},
};
use libp2p::core::{identity::Keypair as IdentityKeypair, PublicKey};
use rand::thread_rng;
use std::fmt::Debug;

pub type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params5x5Bn254>;
pub const SCALE: f64 = 100000000.;

/// The struct for opinions between peers at the specific epoch.
#[derive(Clone, Copy, PartialEq)]
pub struct Opinion {
	pub(crate) k: Epoch,
	pub(crate) c_j: f64,
	pub(crate) t_i: f64,
	pub(crate) sig: SigData<Secp256k1Scalar>,
}

impl Debug for Opinion {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Opinion {{ k: {}, local_trust_score: {}, global_trust_score: {} }}",
			self.k, self.c_j, self.t_i
		)
	}
}

impl Opinion {
	pub fn generate(
		keypair: &IdentityKeypair,
		pubkey_v: &PublicKey,
		k: Epoch,
		c_j: f64,
		t_i: f64,
	) -> Self {
		let mut rng = thread_rng();

		let pair = convert_keypair(keypair);
		let pk_v = convert_pubkey(pubkey_v);

		let c_scaled = Bn256Scalar::from_u128((c_j * SCALE) as u128);
		let t_scaled = Bn256Scalar::from_u128((t_i * SCALE) as u128);
		let k_f = Bn256Scalar::from_u128(k.0 as u128);
		let pk_v_x = Bn256Scalar::from_bytes_wide(&to_wide(pk_v.x.to_bytes()));

		let input = [Bn256Scalar::zero(), k_f, pk_v_x, t_scaled, c_scaled];
		let pos = Posedion5x5::new(input);
		let out = pos.permute()[0];

		let m_hash = Secp256k1Scalar::from_bytes(&out.to_bytes()).unwrap();
		let sig = generate_signature(pair, m_hash, &mut rng).unwrap();
		Self { k, c_j, t_i, sig }
	}

	/// Creates a new opinion.
	pub fn new(sig: SigData<Secp256k1Scalar>, k: Epoch, c_j: f64, t_i: f64) -> Self {
		Self { k, c_j, t_i, sig }
	}

	/// Creates an empty opinion, in a case when we don't have any opinion about
	/// a peer, or the neighbor doesn't have any opinion about us.
	pub fn empty() -> Self {
		let sig_data = SigData::empty();
		Self::new(sig_data, Epoch(0), 0., 0.)
	}

	pub fn verify(&self, pubkey_v: &PublicKey) -> bool {
		if self.t_i == 0. {
			return true;
		}
		verify_signature(&self.sig, &convert_pubkey(pubkey_v))
	}
}

pub fn convert_keypair(kp: &IdentityKeypair) -> Keypair<Secp256k1Affine> {
	match kp {
		IdentityKeypair::Secp256k1(secp_kp) => {
			let mut sk_bytes = secp_kp.secret().to_bytes();
			sk_bytes.reverse();

			let sk = Secp256k1Scalar::from_bytes(&sk_bytes).unwrap();
			let g = Secp256k1Affine::generator();
			let pk = (g * sk).to_affine();

			Keypair::from_pair(sk, pk)
		},
		_ => panic!("Unsupported Keypair"),
	}
}

pub fn convert_pubkey(pk: &PublicKey) -> Secp256k1Affine {
	match pk {
		PublicKey::Secp256k1(secp_pk) => {
			let pk_bytes = secp_pk.encode_uncompressed();
			let mut x_bytes: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
			let mut y_bytes: [u8; 32] = pk_bytes[33..65].try_into().unwrap();
			x_bytes.reverse();
			y_bytes.reverse();

			let x = Secp256k1Base::from_bytes(&x_bytes).unwrap();
			let y = Secp256k1Base::from_bytes(&y_bytes).unwrap();
			Secp256k1Affine::from_xy(x, y).unwrap()
		},
		_ => panic!("Unsupported PublicKey"),
	}
}

pub fn to_wide(p: [u8; 32]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..32].copy_from_slice(&p[..]);
	res
}

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		ecdsa::native::SigData,
		halo2wrong::{curves::secp256k1::Fq as Secp256k1Scalar, halo2::arithmetic::Field},
	};
	use rand::thread_rng;

	#[test]
	fn test_new_opinion() {
		let sig_data = SigData::<Secp256k1Scalar>::empty();
		let k = Epoch(1);
		let local_trust_score = 0.5;
		let global_trust_score = 0.5;
		let opinon = Opinion::new(sig_data, k, local_trust_score, global_trust_score);

		assert_eq!(opinon.k, k);
		assert_eq!(opinon.c_j, local_trust_score);
		assert_eq!(opinon.t_i, global_trust_score);
		assert_eq!(opinon.sig, sig_data);
	}

	#[test]
	fn test_convert_keypair() {
		let mut rng = &mut thread_rng();
		let native_keypair = IdentityKeypair::generate_secp256k1();
		let native_pk = native_keypair.public();

		let halo2_keypair = convert_keypair(&native_keypair);
		let halo2_pk = convert_pubkey(&native_pk);

		let m_hash = Secp256k1Scalar::random(&mut rng);
		let sig_data = generate_signature(halo2_keypair, m_hash, &mut rng).unwrap();

		let res = verify_signature(&sig_data, &halo2_pk);
		assert!(res);
	}

	#[test]
	fn test_generate_opinion() {
		let keypair_i = IdentityKeypair::generate_secp256k1();
		let pubkey_i = keypair_i.public();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = keypair_v.public();

		let k = Epoch(1);
		let local_trust_score = 0.5;
		let global_trust_score = 0.5;

		let opinion = Opinion::generate(
			&keypair_i,
			&pubkey_v,
			k,
			local_trust_score,
			global_trust_score,
		);

		assert!(opinion.verify(&pubkey_i));
	}
}
