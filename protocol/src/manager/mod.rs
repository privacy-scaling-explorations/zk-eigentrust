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
use eigen_trust_circuit::halo2wrong::{
	curves::{
		bn256::{Bn256, Fr as Bn256Scalar, G1Affine},
		group::ff::PrimeField,
	},
	halo2::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
};
use ivp::IVP;
use serde::{Deserialize, Serialize};
use sig::Signature;
use std::collections::HashMap;

/// The peer struct.
pub struct Manager {
	pub(crate) cached_ivps: HashMap<(Bn256Scalar, Bn256Scalar, Epoch, u32), IVP>,
	pub(crate) signatures: HashMap<Bn256Scalar, Signature>,
	empty_ivp: IVP,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Manager {
	/// Creates a new peer.
	pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		let empty = IVP::empty(&params, &pk).unwrap();
		Self {
			cached_ivps: HashMap::new(),
			signatures: HashMap::new(),
			empty_ivp: empty,
			params,
			proving_key: pk,
		}
	}

	pub fn add_signature(&mut self, sig: Signature) {
		self.signatures.insert(sig.pk, sig);
	}

	pub fn get_signature(&self, pk: &Bn256Scalar) -> &Signature {
		self.signatures.get(pk).unwrap()
	}

	/// Calculate the Ivp in the iteration 0
	pub fn calculate_initial_ivps(&mut self, epoch: Epoch) {
		for (i, sig) in self.signatures.values().enumerate() {
			let op_ji = [0.0; MAX_NEIGHBORS];
			let sum: f64 = sig.scores.iter().sum();
			let normalized_score = sig.scores[i] / sum;
			for neighbour in sig.neighbours {
				if neighbour.is_none() {
					continue;
				}
				let neighbour = neighbour.unwrap();
				let proof = IVP::generate(
					sig, neighbour, epoch, 0, op_ji, normalized_score, &self.params,
					&self.proving_key,
				)
				.unwrap();
				self.cached_ivps.insert((sig.pk, neighbour, epoch, 0), proof);
			}
		}
	}

	pub fn calculate_ivps(&mut self, epoch: Epoch, iter: u32) {
		for (i, sig) in self.signatures.values().enumerate() {
			let op_ji = self.get_op_jis(sig, epoch, iter);
			let sum: f64 = sig.scores.iter().sum();
			let normalized_score = sig.scores[i] / sum;
			for neighbour in sig.neighbours {
				if neighbour.is_none() {
					continue;
				}
				let neighbour = neighbour.unwrap();
				let ivp = IVP::generate(
					sig,
					neighbour,
					epoch,
					iter + 1,
					op_ji,
					normalized_score,
					&self.params,
					&self.proving_key,
				)
				.unwrap();
				self.cached_ivps.insert((sig.pk, neighbour, ivp.epoch, ivp.iter), ivp);
			}
		}
	}

	pub fn get_op_jis(&self, sig: &Signature, epoch: Epoch, iter: u32) -> [f64; MAX_NEIGHBORS] {
		let mut op_ji = [0.0; MAX_NEIGHBORS];
		for (i, neighbour) in sig.neighbours.iter().enumerate() {
			if neighbour.is_none() {
				continue;
			}
			let neighbour = neighbour.unwrap();
			let last_ivp =
				self.cached_ivps.get(&(neighbour, sig.pk, epoch, iter)).unwrap_or(&self.empty_ivp);
			op_ji[i] = last_ivp.op;
		}
		op_ji
	}
}
