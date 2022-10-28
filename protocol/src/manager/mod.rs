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

	pub fn get_signature(&self, pk: &Bn256Scalar) -> Result<&Signature, EigenError> {
		self.signatures.get(pk).ok_or(EigenError::SignatureNotFound)
	}

	/// Calculate the Ivp in the iteration 0
	pub fn calculate_initial_ivps(&mut self, epoch: Epoch) {
		for sig in self.signatures.values() {
			let op_ji = [0.0; MAX_NEIGHBORS];
			let sum: f64 = sig.scores.iter().map(|x| x.unwrap_or(0.)).sum();
			for (i, neighbour) in sig.neighbours.iter().enumerate() {
				if neighbour.is_none() {
					continue;
				}
				let neighbour = neighbour.unwrap();
				let normalized_score = sig.scores[i].unwrap() / sum;
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
		for sig in self.signatures.values() {
			let op_ji = self.get_op_jis(sig, epoch, iter);
			let sum: f64 = sig.scores.iter().map(|x| x.unwrap_or(0.)).sum();
			for (i, neighbour) in sig.neighbours.iter().enumerate() {
				if neighbour.is_none() {
					continue;
				}
				let neighbour = neighbour.unwrap();
				let normalized_score = sig.scores[i].unwrap() / sum;
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

	const SK_KEY1: &str = "AF4yAqwCPzpBcit4FtTrHso4BBR9onk7qS9Q1SWSLSaV";
	const SK_KEY2: &str = "7VoQFngkSo36s5yzZtnjtZ5SLe1VGukCZdb5Uc9tSDNC";
	const SK_KEY3: &str = "3wEvtEFktXUBHZHPPmLkDh7oqFLnjTPep1EJ2eBqLtcX";

	#[test]
	fn should_calculate_initial_ivp() {
		let mut rng = thread_rng();
		let params = ParamsKZG::<Bn256>::new(9);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(&mut rng);
		let proving_key = keygen(&params, &random_circuit).unwrap();

		let epoch = Epoch(123);
		let mut manager = Manager::new(params, proving_key);

		let sk1 = scalar_from_bs58(SK_KEY1);
		let pk1 = generate_pk_from_sk(sk1);

		let sk2 = scalar_from_bs58(SK_KEY2);
		let pk2 = generate_pk_from_sk(sk2);

		let sk3 = scalar_from_bs58(SK_KEY3);
		let pk3 = generate_pk_from_sk(sk3);

		let mut neighbours1 = [None; MAX_NEIGHBORS];
		neighbours1[0] = Some(pk2);
		neighbours1[1] = Some(pk3);

		let mut neighbours2 = [None; MAX_NEIGHBORS];
		neighbours2[0] = Some(pk1);
		neighbours2[1] = Some(pk3);

		let mut neighbours3 = [None; MAX_NEIGHBORS];
		neighbours3[0] = Some(pk1);
		neighbours3[1] = Some(pk2);

		let mut scores1 = [None; MAX_NEIGHBORS];
		scores1[0] = Some(10.);
		scores1[1] = Some(20.);
		let mut scores2 = [None; MAX_NEIGHBORS];
		scores2[0] = Some(10.);
		scores2[1] = Some(20.);
		let mut scores3 = [None; MAX_NEIGHBORS];
		scores3[0] = Some(10.);
		scores3[1] = Some(20.);

		let sig1 = Signature::new(sk1, pk1, neighbours1, scores1);
		let sig2 = Signature::new(sk2, pk2, neighbours2, scores2);
		let sig3 = Signature::new(sk3, pk3, neighbours3, scores3);

		manager.add_signature(sig1);
		manager.add_signature(sig2);
		manager.add_signature(sig3);

		manager.calculate_initial_ivps(epoch);

		let ivp12 = manager.cached_ivps.get(&(pk1, pk2, epoch, 0)).unwrap();
		let ivp13 = manager.cached_ivps.get(&(pk1, pk3, epoch, 0)).unwrap();

		let ivp21 = manager.cached_ivps.get(&(pk2, pk1, epoch, 0)).unwrap();
		let ivp23 = manager.cached_ivps.get(&(pk2, pk3, epoch, 0)).unwrap();

		let ivp31 = manager.cached_ivps.get(&(pk3, pk1, epoch, 0)).unwrap();
		let ivp32 = manager.cached_ivps.get(&(pk3, pk2, epoch, 0)).unwrap();

		assert_eq!(ivp12.op, 0.166666665);
		assert_eq!(ivp13.op, 0.333333335);

		assert_eq!(ivp21.op, 0.166666665);
		assert_eq!(ivp23.op, 0.333333335);

		assert_eq!(ivp31.op, 0.166666665);
		assert_eq!(ivp32.op, 0.333333335);
	}

	#[test]
	fn should_calculate_ivp_iterations() {
		let mut rng = thread_rng();
		let params = ParamsKZG::<Bn256>::new(9);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(&mut rng);
		let proving_key = keygen(&params, &random_circuit).unwrap();

		let epoch = Epoch(123);
		let mut manager = Manager::new(params, proving_key);

		let sk1 = scalar_from_bs58(SK_KEY1);
		let pk1 = generate_pk_from_sk(sk1);

		let sk2 = scalar_from_bs58(SK_KEY2);
		let pk2 = generate_pk_from_sk(sk2);

		let sk3 = scalar_from_bs58(SK_KEY3);
		let pk3 = generate_pk_from_sk(sk3);

		let mut neighbours1 = [None; MAX_NEIGHBORS];
		neighbours1[0] = Some(pk2);
		neighbours1[1] = Some(pk3);

		let mut neighbours2 = [None; MAX_NEIGHBORS];
		neighbours2[0] = Some(pk1);
		neighbours2[1] = Some(pk3);

		let mut neighbours3 = [None; MAX_NEIGHBORS];
		neighbours3[0] = Some(pk1);
		neighbours3[1] = Some(pk2);

		let mut scores1 = [None; MAX_NEIGHBORS];
		scores1[0] = Some(10.);
		scores1[1] = Some(20.);
		let mut scores2 = [None; MAX_NEIGHBORS];
		scores2[0] = Some(10.);
		scores2[1] = Some(20.);
		let mut scores3 = [None; MAX_NEIGHBORS];
		scores3[0] = Some(10.);
		scores3[1] = Some(20.);

		let sig1 = Signature::new(sk1, pk1, neighbours1, scores1);
		let sig2 = Signature::new(sk2, pk2, neighbours2, scores2);
		let sig3 = Signature::new(sk3, pk3, neighbours3, scores3);

		manager.add_signature(sig1.clone());
		manager.add_signature(sig2.clone());
		manager.add_signature(sig3.clone());

		manager.calculate_initial_ivps(epoch);

		for i in 0..NUM_ITERATIONS {
			manager.calculate_ivps(epoch, i);
		}

		let ivp12 = manager.cached_ivps.get(&(pk1, pk2, epoch, NUM_ITERATIONS)).unwrap();
		let ivp13 = manager.cached_ivps.get(&(pk1, pk3, epoch, NUM_ITERATIONS)).unwrap();

		let ivp21 = manager.cached_ivps.get(&(pk2, pk1, epoch, NUM_ITERATIONS)).unwrap();
		let ivp23 = manager.cached_ivps.get(&(pk2, pk3, epoch, NUM_ITERATIONS)).unwrap();

		let ivp31 = manager.cached_ivps.get(&(pk3, pk1, epoch, NUM_ITERATIONS)).unwrap();
		let ivp32 = manager.cached_ivps.get(&(pk3, pk2, epoch, NUM_ITERATIONS)).unwrap();

		assert_eq!(ivp12.op, 0.1250571554160951);
		assert_eq!(ivp13.op, 0.2501143145839049);

		assert_eq!(ivp21.op, 0.1778692282213077);
		assert_eq!(ivp23.op, 0.3557384617786923);

		assert_eq!(ivp31.op, 0.1970736213625971);
		assert_eq!(ivp32.op, 0.3941472486374029);

		let op_ji1 = manager.get_op_jis(&sig1, epoch, NUM_ITERATIONS);
		let op_ji2 = manager.get_op_jis(&sig2, epoch, NUM_ITERATIONS);
		let op_ji3 = manager.get_op_jis(&sig3, epoch, NUM_ITERATIONS);

		assert_eq!(op_ji1.iter().sum::<f64>(), 0.3749428495839048);
		assert_eq!(op_ji2.iter().sum::<f64>(), 0.519204404053498);
		assert_eq!(op_ji3.iter().sum::<f64>(), 0.6058527763625972);
	}
}
