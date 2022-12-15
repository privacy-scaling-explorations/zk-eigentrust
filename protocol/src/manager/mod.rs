//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

/// Wrapper around the circuit API
pub mod ivp;
/// Signature implementation
pub mod sig;

use crate::{constants::MAX_NEIGHBORS, epoch::Epoch, error::EigenError};
use eigen_trust_circuit::{
	eddsa::native::PublicKey,
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn256Scalar, G1Affine},
			group::ff::PrimeField,
		},
		halo2::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
	},
};
use ivp::IVP;
use serde::{Deserialize, Serialize};
use sig::Signature;
use std::collections::HashMap;

/// The peer struct.
pub struct Manager {
	pub(crate) cached_ivps: HashMap<(Bn256Scalar, Bn256Scalar, Epoch, u32), IVP>,
	pub(crate) signatures: HashMap<PublicKey, Signature>,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Manager {
	/// Creates a new peer.
	pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		Self { cached_ivps: HashMap::new(), signatures: HashMap::new(), params, proving_key: pk }
	}

	pub fn add_signature(&mut self, sig: Signature) {
		self.signatures.insert(sig.pk.clone(), sig);
	}

	pub fn get_signature(&self, pk: &PublicKey) -> Result<&Signature, EigenError> {
		self.signatures.get(pk).ok_or(EigenError::SignatureNotFound)
	}

	/// Calculate the Ivp in the iteration 0
	pub fn calculate_initial_ivps(&mut self, epoch: Epoch) {}

	pub fn calculate_ivps(&mut self, epoch: Epoch, iter: u32) {}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		constants::{NUM_BOOTSTRAP_PEERS, NUM_ITERATIONS},
		utils::{generate_pk_from_sk, scalar_from_bs58},
	};
	use eigen_trust_circuit::{
		halo2wrong::{
			curves::bn256::Bn256,
			halo2::{
				arithmetic::Field,
				poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
			},
		},
		params::poseidon_bn254_5x5::Params,
		utils::{keygen, random_circuit},
	};
	use rand::thread_rng;

	#[test]
	fn should_calculate_initial_ivp() {}

	#[test]
	fn should_calculate_ivp_iterations() {}
}
