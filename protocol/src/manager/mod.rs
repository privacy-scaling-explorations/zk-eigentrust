//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

/// Attestation implementation
pub mod attestation;
/// Wrapper around the circuit API
pub mod prover;

use crate::{epoch::Epoch, error::EigenError};
use attestation::Attestation;
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
use prover::EigenTrustProver;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NUM_ITER: usize = 10;
pub const NUM_NEIGHBOURS: usize = 5;
pub const INITIAL_SCORE: u128 = 1000;
pub const SCALE: u128 = 1000;

/// The peer struct.
pub struct Manager {
	pub(crate) cached_proofs: HashMap<Epoch, EigenTrustProver>,
	pub(crate) attestations: HashMap<PublicKey, Attestation>,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Manager {
	/// Creates a new peer.
	pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		Self {
			cached_proofs: HashMap::new(),
			attestations: HashMap::new(),
			params,
			proving_key: pk,
		}
	}

	pub fn add_attestation(&mut self, sig: Attestation) {
		self.attestations.insert(sig.pk.clone(), sig);
	}

	pub fn get_attestation(&self, pk: &PublicKey) -> Result<&Attestation, EigenError> {
		self.attestations.get(pk).ok_or(EigenError::AttestationNotFound)
	}

	pub fn calculate_proofs(&mut self, epoch: Epoch) {}
}

#[cfg(test)]
mod test {

	#[test]
	fn should_calculate_initial_ivp() {}

	#[test]
	fn should_calculate_ivp_iterations() {}
}
