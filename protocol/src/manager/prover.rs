use std::vec;

use super::{Attestation, INITIAL_SCORE, NUM_ITER, NUM_NEIGHBOURS, SCALE};
use crate::{
	epoch::Epoch,
	error::EigenError,
	utils::{scalar_from_bs58, to_wide_bytes},
};
use bs58::decode::Error as Bs58Error;
use eigen_trust_circuit::{
	circuit::{native, EigenTrust, PoseidonNativeHasher},
	eddsa::native::{PublicKey, Signature},
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Scalar, G1Affine},
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
};
use rand::thread_rng;

#[derive(Clone, Debug)]
pub struct EigenTrustProver {
	pks: [PublicKey; NUM_NEIGHBOURS],
	signatures: [Signature; NUM_NEIGHBOURS],
	ops: [[Scalar; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
	messages: [Scalar; NUM_NEIGHBOURS],
	pk: ProvingKey<G1Affine>,
	params: ParamsKZG<Bn256>,
}

impl EigenTrustProver {
	pub fn new(
		pks: [PublicKey; NUM_NEIGHBOURS], signatures: [Signature; NUM_NEIGHBOURS],
		ops: [[Scalar; NUM_NEIGHBOURS]; NUM_NEIGHBOURS], messages: [Scalar; NUM_NEIGHBOURS],
		pk: ProvingKey<G1Affine>, params: ParamsKZG<Bn256>,
	) -> Self {
		Self { pks, signatures, ops, messages, pk, params }
	}

	/// Creates a new IVP.
	pub fn generate(&self) -> Result<Vec<u8>, EigenError> {
		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			self.pks.clone(),
			self.signatures.clone(),
			self.ops,
			self.messages,
		);
		Err(EigenError::ProvingError)
	}

	/// Verifies the proof.
	pub fn verify(&self, scores: [Scalar; NUM_NEIGHBOURS]) -> Result<bool, EigenError> {
		Err(EigenError::VerificationError)
	}
}

#[cfg(test)]
mod test {

	#[test]
	fn ivp_should_create_empty() {}

	#[test]
	fn ivp_should_verify() {}
}
