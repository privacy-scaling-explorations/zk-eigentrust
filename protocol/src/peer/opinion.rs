use std::vec;

use super::pubkey::Pubkey;
use crate::{
	constants::*,
	utils::{extract_sk_limbs, to_wide_bytes},
	EigenError, Epoch,
};
use bs58::decode::Error as Bs58Error;
use eigen_trust_circuit::{
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn256Scalar, G1Affine},
			FieldExt,
		},
		halo2::{
			plonk::{ProvingKey, VerifyingKey},
			poly::kzg::commitment::ParamsKZG,
		},
	},
	poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254},
	utils::{prove, verify},
	EigenTrustCircuit,
};
use libp2p::core::identity::Keypair as IdentityKeypair;
use rand::thread_rng;

pub type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params5x5Bn254>;
pub type ETCircuit =
	EigenTrustCircuit<Bn256Scalar, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>;
pub const SCALE: f64 = 100000000.;

#[derive(Clone, Debug, PartialEq)]
pub struct Opinion {
	pub(crate) epoch: Epoch,
	pub(crate) iter: u32,
	pub(crate) op: f64,
	pub(crate) proof_bytes: Vec<u8>,
	pub(crate) m_hash: [u8; 32],
}

impl Opinion {
	pub fn new(epoch: Epoch, iter: u32, op: f64, proof_bytes: Vec<u8>) -> Self {
		Self { epoch, iter, op, proof_bytes, m_hash: [0; 32] }
	}

	/// Creates a new opinion.
	pub fn generate(
		kp: &IdentityKeypair, pubkey_v: &Pubkey, epoch: Epoch, k: u32, op_ji: [f64; MAX_NEIGHBORS],
		c_v: f64, params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		let mut rng = thread_rng();

		let sk = extract_sk_limbs(kp)?;
		let input = [Bn256Scalar::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pos = Posedion5x5::new(input);
		let pk_p = pos.permute()[0];

		let pk_v = pubkey_v.value();

		let bootstrap_pubkeys = BOOTSTRAP_PEERS
			.try_map(|key| {
				let bytes = &bs58::decode(key).into_vec()?;
				Ok(Bn256Scalar::from_bytes_wide(&to_wide_bytes(bytes)))
			})
			.map_err(|_: Bs58Error| EigenError::InvalidBootstrapPubkey)?;
		let bootstrap_score_scaled = (BOOTSTRAP_SCORE * SCALE).round() as u128;
		// Turn into scaled values and round the to avoid rounding errors.
		let op_ji_scaled = op_ji.map(|op| (op * SCALE).round() as u128);
		let c_v_scaled = (c_v * SCALE).round() as u128;

		let t_i_scaled = op_ji_scaled.iter().sum();

		let is_bootstrap = bootstrap_pubkeys.contains(&pk_p);
		let is_first_iter = k == 0;
		let t_i_final =
			if is_bootstrap && is_first_iter { bootstrap_score_scaled } else { t_i_scaled };

		let op_v_scaled = t_i_final * c_v_scaled;
		let op_v_unscaled = (op_v_scaled as f64) / (SCALE * SCALE);
		// Converting into field
		let op_ji_f = op_ji_scaled.map(Bn256Scalar::from_u128);
		let c_v_f = Bn256Scalar::from_u128(c_v_scaled);
		let op_v_f = Bn256Scalar::from_u128(op_v_scaled);
		let epoch_f = Bn256Scalar::from(epoch.0);
		let iter_f = Bn256Scalar::from_u128(u128::from(k));
		let bootstrap_score_f = Bn256Scalar::from_u128(bootstrap_score_scaled);

		let m_hash_input = [epoch_f, iter_f, op_v_f, pk_v, pk_p];
		let pos = Posedion5x5::new(m_hash_input);
		let m_hash = pos.permute()[0];

		let circuit = ETCircuit::new(
			pk_v, epoch_f, iter_f, sk, op_ji_f, c_v_f, bootstrap_pubkeys, bootstrap_score_f,
		);

		let pub_ins = vec![m_hash];

		let proof_bytes = prove(params, circuit, &[&pub_ins], pk, &mut rng)
			.map_err(|_| EigenError::ProvingError)?;

		// Sanity check
		let proof_res = verify(params, &[&pub_ins], &proof_bytes, pk.get_vk()).map_err(|e| {
			println!("{}", e);
			EigenError::VerificationError
		})?;
		assert!(proof_res);

		Ok(Self { epoch, iter: k, op: op_v_unscaled, proof_bytes, m_hash: m_hash.to_bytes() })
	}

	pub fn empty(params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>) -> Result<Self, EigenError> {
		let kp: IdentityKeypair = IdentityKeypair::generate_secp256k1();
		let pubkey_v = Pubkey::from_keypair(&kp).unwrap();
		let op_ji: [f64; MAX_NEIGHBORS] = [0.; MAX_NEIGHBORS];
		let c_v: f64 = 0.;
		let k = 0;
		let epoch = Epoch(0);

		Self::generate(&kp, &pubkey_v, epoch, k, op_ji, c_v, params, pk)
	}

	/// Verifies the proof.
	pub fn verify(
		&self, pubkey_p: &Pubkey, kp: &IdentityKeypair, params: &ParamsKZG<Bn256>,
		vk: &VerifyingKey<G1Affine>,
	) -> Result<bool, EigenError> {
		let pk_p = pubkey_p.value();
		let sk = extract_sk_limbs(kp)?;
		let input = [Bn256Scalar::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pos = Posedion5x5::new(input);
		let pk_v = pos.permute()[0];

		let op_v_scaled = (self.op * SCALE * SCALE).round() as u128;
		let epoch_f = Bn256Scalar::from_u128(u128::from(self.epoch.0));
		let iter_f = Bn256Scalar::from_u128(u128::from(self.iter));
		let op_v_f = Bn256Scalar::from_u128(op_v_scaled);

		let m_hash_input = [epoch_f, iter_f, op_v_f, pk_v, pk_p];
		let pos = Posedion5x5::new(m_hash_input);
		let m_hash = pos.permute()[0];
		let m_hash_passed = Bn256Scalar::from_bytes(&self.m_hash).unwrap();

		let final_hash = if op_v_f == Bn256Scalar::zero() { m_hash_passed } else { m_hash };

		let pub_ins = vec![final_hash];

		let proof_res = verify(params, &[&pub_ins], &self.proof_bytes, vk).map_err(|e| {
			println!("{}", e);
			EigenError::VerificationError
		})?;

		Ok(proof_res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::keypair_from_sk_bytes;
	use eigen_trust_circuit::{
		halo2wrong::halo2::poly::commitment::ParamsProver,
		utils::{keygen, random_circuit},
	};

	#[test]
	fn should_verify_empty_opinion() {
		let rng = &mut thread_rng();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(9);

		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let op = Opinion::empty(&params, &pk).unwrap();
		let res = op.verify(&local_pubkey, &keypair_v, &params, &pk.get_vk()).unwrap();
		assert!(res);
	}

	#[test]
	fn test_new_proof_generate() {
		let rng = &mut thread_rng();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = Pubkey::from_keypair(&keypair_v).unwrap();

		let epoch = Epoch(1);
		let iter = 0;
		let op_ji = [0.1; MAX_NEIGHBORS];
		let c_v = 0.1;

		let params = ParamsKZG::<Bn256>::new(9);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let proof = Opinion::generate(
			&local_keypair, &pubkey_v, epoch, iter, op_ji, c_v, &params, &pk,
		)
		.unwrap();

		assert!(proof.verify(&local_pubkey, &keypair_v, &params, pk.get_vk()).unwrap());
	}

	#[test]
	fn test_bootstrap_proof() {
		let rng = &mut thread_rng();
		let sk = "AF4yAqwCPzpBcit4FtTrHso4BBR9onk7qS9Q1SWSLSaV";
		let sk_bytes1 = bs58::decode(sk).into_vec().unwrap();
		let local_keypair = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = Pubkey::from_keypair(&keypair_v).unwrap();

		let epoch = Epoch(1);
		let iter = 0;
		let op_ji = [0.1; MAX_NEIGHBORS];
		let c_v = 0.1;

		let params = ParamsKZG::<Bn256>::new(9);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let opinion = Opinion::generate(
			&local_keypair, &pubkey_v, epoch, iter, op_ji, c_v, &params, &pk,
		)
		.unwrap();

		assert_eq!(opinion.op, BOOTSTRAP_SCORE * c_v);

		assert!(opinion.verify(&local_pubkey, &keypair_v, &params, pk.get_vk()).unwrap());
	}
}
