//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

pub mod opinion;
pub mod proof;

use crate::{epoch::Epoch, EigenError};
use libp2p::{core::PublicKey, identity::Keypair, PeerId};
use opinion::Opinion;
use std::collections::HashMap;

/// The number of neighbors the peer can have.
/// This is also the maximum number of peers that can be connected to the
/// node.
pub const MAX_NEIGHBORS: usize = 256;

/// Min score for each peer.
const MIN_SCORE: f64 = 0.1;

/// The peer struct.
pub struct Peer {
	neighbors: [Option<PeerId>; MAX_NEIGHBORS],
	pubkeys: HashMap<PeerId, PublicKey>,
	neighbor_scores: HashMap<PeerId, u32>,
	cached_neighbor_opinion: HashMap<(PeerId, Epoch), Opinion>,
	cached_local_opinion: HashMap<(PeerId, Epoch), Opinion>,
	keypair: Keypair,
}

impl Peer {
	/// Creates a new peer.
	pub fn new(keypair: Keypair) -> Self {
		Peer {
			neighbors: [None; MAX_NEIGHBORS],
			pubkeys: HashMap::new(),
			neighbor_scores: HashMap::new(),
			cached_neighbor_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			keypair,
		}
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

	/// Identifies a neighbor, by saving its public key.
	pub fn identify_neighbor(&mut self, peer_id: PeerId, pubkey: PublicKey) {
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

	/// Calculate the global trust score of the peer in the specified epoch.
	/// We do this by taking the sum of neighbor's opinions and weighting it by
	/// the pre trust weight. Then we are adding it with the weighted pre-trust
	/// score.
	pub fn calculate_global_trust_score(&self, epoch: Epoch) -> f64 {
		let mut global_score = 0.;

		for peer_id in self.neighbors() {
			let opinion = self.get_neighbor_opinion(&(peer_id, epoch));
			global_score += opinion.global_trust_score * opinion.local_trust_score;
		}
		// We are adding the min score to the global score.
		global_score = MIN_SCORE + global_score;

		global_score
	}

	/// Calculate the local trust score toward all neighbors in the specified
	/// epoch.
	pub fn calculate_local_opinions(&mut self, k: Epoch) {
		let global_score = self.calculate_global_trust_score(k);

		let mut opinions = Vec::new();
		for peer_id in self.neighbors() {
			let score = self.neighbor_scores.get(&peer_id).unwrap_or(&0);
			let normalized_score = self.get_normalized_score(*score);
			let pubkey = self.pubkeys.get(&peer_id).unwrap();
			let opinion = Opinion::generate(
				&self.keypair,
				pubkey,
				k.next(),
				normalized_score,
				global_score,
			);

			opinions.push((peer_id, opinion));
		}

		for (peer_id, opinion) in opinions {
			self.cache_local_opinion((peer_id, opinion.k), opinion);
		}
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
	pub fn get_local_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		let pubkey = self.pubkeys.get(&key.0).unwrap();
		*self
			.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(&self.keypair, pubkey, key.1))
	}

	/// Caches the local opinion towards a peer in a specified epoch.
	pub fn cache_local_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_local_opinion.insert(key, opinion);
	}

	/// Returns the neighbor's opinion towards us in a specified epoch.
	pub fn get_neighbor_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		let invalid_pair = Keypair::generate_secp256k1();
		let invalid_pubkey = invalid_pair.public();
		*self
			.cached_neighbor_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(&invalid_pair, &invalid_pubkey, key.1))
	}

	/// Caches the neighbor opinion towards us in specified epoch.
	pub fn cache_neighbor_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_neighbor_opinion.insert(key, opinion);
	}

	/// Get the public key of a neighbor.
	pub fn get_pub_key(&self, peer_id: PeerId) -> PublicKey {
		self.pubkeys.get(&peer_id).cloned().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use eigen_trust_circuit::ecdsa::SigData;
	use libp2p::core::identity::Keypair;

	#[test]
	fn should_create_opinion() {
		let sig = SigData::empty();
		let opinion = Opinion::new(sig, Epoch(0), 0.5, 0.5);
		assert_eq!(opinion.k, Epoch(0));
		assert_eq!(opinion.global_trust_score, 0.5);
		assert_eq!(opinion.local_trust_score, 0.5);
	}

	#[test]
	fn should_create_peer() {
		let kp = Keypair::generate_secp256k1();
		let peer = Peer::new(kp);
		assert_eq!(peer.get_sum_of_scores(), 0);
	}

	#[test]
	fn should_cache_local_and_global_opinion() {
		let kp = Keypair::generate_secp256k1();
		let mut peer = Peer::new(kp);


		let epoch = Epoch(0);
		let neighbor_id = PeerId::random();
		let sig = SigData::empty();

		let pubkey = Keypair::generate_secp256k1().public();
		peer.identify_neighbor(neighbor_id, pubkey);

		let opinion = Opinion::new(sig, epoch, 0.5, 0.5);
		peer.cache_local_opinion((neighbor_id, epoch), opinion);
		peer.cache_neighbor_opinion((neighbor_id, epoch), opinion);

		assert_eq!(peer.get_local_opinion(&(neighbor_id, epoch)), opinion);
		assert_eq!(peer.get_neighbor_opinion(&(neighbor_id, epoch)), opinion);
	}

	#[test]
	fn should_add_and_remove_neghbours() {
		let kp = Keypair::generate_secp256k1();
		let mut peer = Peer::new(kp);
		let neighbor_id = PeerId::random();

		peer.add_neighbor(neighbor_id).unwrap();
		let num_neighbors = peer.neighbors().len();
		assert_eq!(num_neighbors, 1);

		peer.remove_neighbor(neighbor_id);
		let num_neighbors = peer.neighbors().len();
		assert_eq!(num_neighbors, 0);
	}

	#[test]
	fn should_add_neighbors_and_calculate_global_score() {
		let min_score = 0.1;
		let kp = Keypair::generate_secp256k1();
		let mut peer = Peer::new(kp);

		let epoch = Epoch(0);
		for _ in 0..256 {
			let peer_id = PeerId::random();
			peer.add_neighbor(peer_id).unwrap();
			peer.set_score(peer_id, 5);
			let sig = SigData::empty();
			let opinion = Opinion::new(sig, epoch, 0.1, 0.1);
			peer.cache_neighbor_opinion((peer_id, epoch), opinion);
		}

		let global_score = peer.calculate_global_trust_score(epoch);

		let mut true_global_score = 0.0;
		for _ in 0..256 {
			true_global_score += 0.01;
		}
		let boostrap_score = min_score + true_global_score;

		assert_eq!(boostrap_score, global_score);
	}
}
