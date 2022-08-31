//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

pub mod opinion;
pub mod pubkey;
pub mod utils;

use crate::{constants::MAX_NEIGHBORS, EigenError};
use eigen_trust_circuit::halo2wrong::{
	curves::bn256::{Bn256, G1Affine},
	halo2::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
};
use libp2p::{core::PublicKey, identity::Keypair, PeerId};
use opinion::Opinion;
use pubkey::Pubkey;
use std::collections::HashMap;

/// The peer struct.
pub struct Peer {
	pub(crate) neighbors: [Option<PeerId>; MAX_NEIGHBORS],
	pubkeys_native: HashMap<PeerId, PublicKey>,
	pubkeys: HashMap<PeerId, Pubkey>,
	neighbor_scores: HashMap<PeerId, u32>,
	cached_neighbor_opinion: HashMap<(PeerId, u8), Opinion>,
	cached_local_opinion: HashMap<(PeerId, u8), Opinion>,
	keypair: Keypair,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Peer {
	/// Creates a new peer.
	pub fn new(
		keypair: Keypair,
		params: ParamsKZG<Bn256>,
		pk: ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		Ok(Peer {
			neighbors: [None; MAX_NEIGHBORS],
			pubkeys_native: HashMap::new(),
			pubkeys: HashMap::new(),
			neighbor_scores: HashMap::new(),
			cached_neighbor_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			keypair,
			params,
			proving_key: pk,
		})
	}

	/// Adds a neighbor in the first available spot.
	pub fn add_neighbor(&mut self, peer_id: PeerId) -> Result<(), EigenError> {
		if self.neighbors.contains(&Some(peer_id)) {
			return Ok(());
		}
		let index = self
			.neighbors
			.iter()
			.position(|&x| x.is_none())
			.ok_or(EigenError::MaxNeighboursReached)?;
		self.neighbors[index] = Some(peer_id);
		Ok(())
	}

	/// Identifies a neighbor, by saving its native public key.
	pub fn identify_neighbor_native(&mut self, peer_id: PeerId, pubkey: PublicKey) {
		self.pubkeys_native.insert(peer_id, pubkey);
	}

	/// Identifies a neighbor, by saving its public key.
	pub fn identify_neighbor(&mut self, peer_id: PeerId, pubkey: Pubkey) {
		self.pubkeys.insert(peer_id, pubkey);
	}

	/// Removes a neighbor, if found.
	pub fn remove_neighbor(&mut self, peer_id: PeerId) {
		let index_res = self.neighbors.iter().position(|&x| x == Some(peer_id));
		if let Some(index) = index_res {
			self.neighbors[index] = None;
		}
	}

	/// Returns the neighbors of the peer.
	pub fn neighbors(&self) -> Vec<PeerId> {
		self.neighbors.iter().filter_map(|&x| x).collect()
	}

	/// Set the local score towards a neighbor.
	pub fn set_score(&mut self, peer_id: PeerId, score: u32) {
		self.neighbor_scores.insert(peer_id, score);
	}

	/// Calculate the local trust score toward all neighbors in the specified
	/// epoch and generate zk proof of it.
	pub fn calculate_local_opinion(&mut self, peer_id: PeerId, k: u8) {
		let score = self.neighbor_scores.get(&peer_id).unwrap_or(&0);

		let op_ji = self.get_neighbor_opinions_at(k - 1);
		let normalized_score = self.get_normalized_score(*score);
		let pubkey_op = self.get_pub_key(peer_id);
		let opinion = if let Some(pubkey) = pubkey_op {
			Opinion::generate(
				&self.keypair,
				&pubkey,
				k,
				op_ji,
				normalized_score,
				&self.params,
				&self.proving_key,
			)
			.unwrap_or_else(|e| {
				log::debug!("Error while generating opinion for {:?}: {:?}", peer_id, e);
				Opinion::empty(k, &self.params, &self.proving_key).unwrap()
			})
		} else {
			log::debug!(
				"Pubkey not found for {:?}, generating empty opinion.",
				peer_id
			);
			Opinion::empty(k, &self.params, &self.proving_key).unwrap()
		};

		self.cache_local_opinion((peer_id, opinion.iter), opinion);
	}

	/// Returns all of the opinions of the neighbors in the specified epoch.
	pub fn get_neighbor_opinions_at(&self, k: u8) -> [f64; MAX_NEIGHBORS] {
		let mut scores: [f64; MAX_NEIGHBORS] = [0.; MAX_NEIGHBORS];
		for (i, peer) in self.neighbors.iter().enumerate() {
			let peer_pk_pair = peer.and_then(|peer_id| {
				let pub_k = self.get_pub_key(peer_id);
				pub_k.map(|pk| (peer_id, pk))
			});

			peer_pk_pair.map(|(peer_id, pubkey_p)| {
				let opinion = self.get_neighbor_opinion(&(peer_id, k));
				let vk = self.proving_key.get_vk();

				if opinion.verify(&pubkey_p, &self.keypair, &self.params, vk) == Ok(true) {
					scores[i] = opinion.op;
				}
			});
		}
		scores
	}

	/// Calculate the global trust score at the specified epoch.
	pub fn global_trust_score_at(&self, at: u8) -> f64 {
		let op_ji = self.get_neighbor_opinions_at(at - 1);
		op_ji.iter().sum()
	}

	/// Returns sum of local scores.
	pub fn get_sum_of_scores(&self) -> u32 {
		let mut sum = 0;
		for peer_id in self.neighbors() {
			let score = self.neighbor_scores.get(&peer_id).unwrap_or(&0);
			sum += score;
		}
		sum
	}

	/// Returns the normalized score.
	pub fn get_normalized_score(&self, score: u32) -> f64 {
		let sum = self.get_sum_of_scores();
		let f_raw_score = f64::from(score);
		let f_sum = f64::from(sum);
		f_raw_score / f_sum
	}

	/// Returns the local score towards a neighbor in a specified epoch.
	pub fn get_local_opinion(&self, key: &(PeerId, u8)) -> Opinion {
		self.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1, &self.params, &self.proving_key).unwrap())
			.clone()
	}

	/// Caches the local opinion towards a peer in a specified epoch.
	pub fn cache_local_opinion(&mut self, key: (PeerId, u8), opinion: Opinion) {
		self.cached_local_opinion.insert(key, opinion);
	}

	/// Returns the neighbor's opinion towards us in a specified epoch.
	pub fn get_neighbor_opinion(&self, key: &(PeerId, u8)) -> Opinion {
		self.cached_neighbor_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1, &self.params, &self.proving_key).unwrap())
			.clone()
	}

	/// Caches the neighbor opinion towards us in specified epoch.
	pub fn cache_neighbor_opinion(&mut self, key: (PeerId, u8), opinion: Opinion) {
		self.cached_neighbor_opinion.insert(key, opinion);
	}

	/// Get the native public key of a neighbor.
	pub fn get_pub_key_native(&self, peer_id: PeerId) -> Option<PublicKey> {
		self.pubkeys_native.get(&peer_id).cloned()
	}

	/// Get the public key of a neighbor.
	pub fn get_pub_key(&self, peer_id: PeerId) -> Option<Pubkey> {
		self.pubkeys.get(&peer_id).cloned()
	}

	/// Get the keypair for this peer.
	pub fn get_keypair(&self) -> &Keypair {
		&self.keypair
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::NUM_BOOTSTRAP_PEERS;
	use eigen_trust_circuit::{
		halo2wrong::halo2::poly::commitment::ParamsProver,
		poseidon::params::bn254_5x5::Params5x5Bn254,
		utils::{keygen, random_circuit},
	};
	use libp2p::core::identity::Keypair;
	use rand::thread_rng;

	#[test]
	fn should_create_peer() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let peer = Peer::new(kp, params, pk).unwrap();
		assert_eq!(peer.get_sum_of_scores(), 0);
	}

	#[test]
	fn should_cache_local_and_global_opinion() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let mut peer = Peer::new(kp, params.clone(), pk.clone()).unwrap();

		let iter = 0;
		let neighbor_id = PeerId::random();

		let pubkey = Keypair::generate_secp256k1().public();
		peer.identify_neighbor_native(neighbor_id, pubkey);

		let opinion = Opinion::empty(iter, &params, &pk).unwrap();
		peer.cache_local_opinion((neighbor_id, iter), opinion.clone());
		peer.cache_neighbor_opinion((neighbor_id, iter), opinion.clone());

		assert_eq!(peer.get_local_opinion(&(neighbor_id, iter)), opinion);
		assert_eq!(peer.get_neighbor_opinion(&(neighbor_id, iter)), opinion);
	}

	#[test]
	fn should_add_and_remove_neghbours() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let mut peer = Peer::new(kp, params, pk).unwrap();
		let neighbor_id = PeerId::random();

		peer.add_neighbor(neighbor_id).unwrap();
		let num_neighbors = peer.neighbors().len();
		assert_eq!(num_neighbors, 1);

		peer.remove_neighbor(neighbor_id);
		let num_neighbors = peer.neighbors().len();
		assert_eq!(num_neighbors, 0);
	}

	// #[test]
	// fn should_add_neighbors_and_calculate_global_score() {
	// 	let rng = &mut thread_rng();
	// 	let local_keypair = Keypair::generate_secp256k1();
	// 	let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

	// 	let params = ParamsKZG::<Bn256>::new(9);
	// 	let random_circuit =
	// 		random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS,
	// Params5x5Bn254>(rng); 	let pk = keygen(&params, &random_circuit).unwrap();

	// 	let mut peer = Peer::new(local_keypair.clone(), params.clone(),
	// pk.clone()).unwrap();

	// 	let iter = 3;
	// 	for _ in 0..4 {
	// 		let kp = Keypair::generate_secp256k1();
	// 		let pubkey = Pubkey::from_keypair(&kp).unwrap();
	// 		let peer_id = kp.public().to_peer_id();

	// 		peer.add_neighbor(peer_id).unwrap();
	// 		peer.identify_neighbor(peer_id, pubkey.clone());
	// 		peer.set_score(peer_id, 5);

	// 		// Create neighbor opinion.
	// 		let mut op_ji = [0.; MAX_NEIGHBORS];
	// 		op_ji[0] = 0.1;
	// 		let c_v = 1.;
	// 		let opinion =
	// 			Opinion::generate(&kp, &local_pubkey, iter, op_ji, c_v, &params,
	// &pk).unwrap();

	// 		// Sanity check
	// 		assert!(opinion
	// 			.verify(&pubkey, &local_keypair, &params, &pk.get_vk())
	// 			.unwrap());

	// 		// Cache neighbor opinion.
	// 		peer.cache_neighbor_opinion((peer_id, iter), opinion);
	// 	}

	// 	for peer_id in peer.neighbors() {
	// 		peer.calculate_local_opinion(peer_id, epoch.next());
	// 	}

	// 	let t_i = peer.global_trust_score_at(epoch.next());
	// 	assert_eq!(t_i, 0.4);
	// 	let c_v = t_i * 0.25;

	// 	for peer_id in peer.neighbors() {
	// 		let opinion = peer.get_local_opinion(&(peer_id, epoch.next()));
	// 		assert_eq!(opinion.op, c_v);
	// 	}
	// }
}
