use std::vec;

use super::Signature;
use crate::{
	constants::*,
	epoch::Epoch,
	error::EigenError,
	utils::{scalar_from_bs58, to_wide_bytes},
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
	params::poseidon_bn254_5x5::Params,
	poseidon::native::Poseidon,
	utils::{prove, verify},
	EigenTrustCircuit,
};
use libp2p::core::identity::Keypair as IdentityKeypair;
use rand::thread_rng;

pub type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params>;
pub type ETCircuit = EigenTrustCircuit<Bn256Scalar, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>;
pub const SCALE: f64 = 100000000.;

#[derive(Clone, Debug, PartialEq)]
pub struct IVP {
	pub(crate) epoch: Epoch,
	pub(crate) iter: u32,
	pub(crate) op: f64,
	pub(crate) proof_bytes: Vec<u8>,
	pub(crate) m_hash: [u8; 32],
}

impl IVP {
	pub fn new(epoch: Epoch, iter: u32, op: f64, proof_bytes: Vec<u8>) -> Self {
		Self { epoch, iter, op, proof_bytes, m_hash: [0; 32] }
	}

	/// Creates a new IVP.
	pub fn generate(
		sig: &Signature, pk_v: Bn256Scalar, epoch: Epoch, k: u32, op_ji: [f64; MAX_NEIGHBORS],
		c_v: f64, params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		Err(EigenError::ProvingError)
	}

	/// Verifies the proof.
	pub fn verify(
		&self, pk_v: Bn256Scalar, pubkey_p: Bn256Scalar, params: &ParamsKZG<Bn256>,
		vk: &VerifyingKey<G1Affine>,
	) -> Result<bool, EigenError> {
		Err(EigenError::VerificationError)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		halo2wrong::{
			curves::bn256::Bn256,
			halo2::{
				arithmetic::Field,
				poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
			},
		},
		utils::{keygen, random_circuit},
	};

	#[test]
	fn ivp_should_create_empty() {}

	#[test]
	fn ivp_should_verify() {}
}
