//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

pub mod opinion;
pub mod proof;

use crate::{epoch::Epoch, EigenError};
use eigen_trust_circuit::{
	ecdsa::Keypair,
	halo2wrong::{
		curves::{
			bn256::Bn256,
			group::ff::PrimeField,
			secp256k1::{Fp as Secp256k1Base, Fq as Secp256k1Scalar, Secp256k1Affine},
		},
		halo2::poly::kzg::commitment::ParamsKZG,
	},
};
use libp2p::{core::PublicKey, identity::Keypair as IdentityKeypair, PeerId};
use opinion::Opinion;
use proof::Proof;
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
	pubkeys: [Option<PublicKey>; MAX_NEIGHBORS],
	neighbor_scores: HashMap<PeerId, u32>,
	cached_neighbor_opinion: HashMap<(PeerId, Epoch), Opinion>,
	cached_local_opinion: HashMap<(PeerId, Epoch), Opinion>,
	proofs: HashMap<Epoch, Proof>,
	keypair: Keypair<Secp256k1Affine>,
	params: ParamsKZG<Bn256>,
}

impl Peer {
	/// Creates a new peer.
	pub fn new(keypair: IdentityKeypair, params: ParamsKZG<Bn256>) -> Self {
		let kp = match keypair {
			IdentityKeypair::Secp256k1(secp_kp) => {
				let sk_bytes = secp_kp.secret().to_bytes();
				let pk_bytes = secp_kp.public().encode_uncompressed();

				let sk = Secp256k1Scalar::from_bytes(&sk_bytes).unwrap();
				// let pk = Secp256k1Compressed(pk_bytes);
				let pk = Secp256k1Affine {
					x: Secp256k1Base::from_repr(pk_bytes[1..33].try_into().unwrap()).unwrap(),
					y: Secp256k1Base::from_repr(pk_bytes[33..65].try_into().unwrap()).unwrap(),
				};

				Keypair::from_pair(sk, pk)
			},
			_ => panic!("unsupported keypair"),
		};
		Peer {
			neighbors: [None; MAX_NEIGHBORS],
			pubkeys: [(); MAX_NEIGHBORS].map(|_| None),
			neighbor_scores: HashMap::new(),
			cached_neighbor_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			proofs: HashMap::new(),
			keypair: kp,
			params,
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
	pub fn identify_neighbor(
		&mut self,
		peer_id: PeerId,
		pubkey: PublicKey,
	) -> Result<(), EigenError> {
		let index_res = self.neighbors.iter().position(|&x| x == Some(peer_id));
		match index_res {
			Some(index) => {
				self.pubkeys[index] = Some(pubkey);
				Ok(())
			},
			None => Err(EigenError::InvalidPeerId),
		}
	}

	/// Removes a neighbor, if found.
	pub fn remove_neighbor(&mut self, peer_id: PeerId) {
		let index_res = self.neighbors.iter().position(|&x| x == Some(peer_id));
		if let Some(index) = index_res {
			self.neighbors[index] = None;
			self.pubkeys[index] = None;
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
			global_score += opinion.product;
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
			let opinion = Opinion::new(k.next(), normalized_score, global_score);

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
		*self
			.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	/// Caches the local opinion towards a peer in a specified epoch.
	pub fn cache_local_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_local_opinion.insert(key, opinion);
	}

	/// Returns the neighbor's opinion towards us in a specified epoch.
	pub fn get_neighbor_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self
			.cached_neighbor_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	/// Caches the neighbor opinion towards us in specified epoch.
	pub fn cache_neighbor_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_neighbor_opinion.insert(key, opinion);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use eigen_trust_circuit::halo2wrong::halo2::poly::commitment::ParamsProver;
	use libp2p::core::identity::Keypair;

	#[test]
	fn should_create_opinion() {
		let opinion = Opinion::new(Epoch(0), 0.5, 0.5);
		assert_eq!(opinion.k, Epoch(0));
		assert_eq!(opinion.global_trust_score, 0.5);
		assert_eq!(opinion.local_trust_score, 0.5);
		assert_eq!(opinion.product, 0.25);
	}

	#[test]
	fn should_create_peer() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(1);
		let peer = Peer::new(kp, params);
		assert_eq!(peer.get_sum_of_scores(), 0);
	}

	#[test]
	fn should_cache_local_and_global_opinion() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(1);
		let mut peer = Peer::new(kp, params);

		let epoch = Epoch(0);
		let neighbor_id = PeerId::random();
		let opinion = Opinion::new(epoch, 0.5, 0.5);
		peer.cache_local_opinion((neighbor_id, epoch), opinion);
		peer.cache_neighbor_opinion((neighbor_id, epoch), opinion);

		assert_eq!(peer.get_local_opinion(&(neighbor_id, epoch)), opinion);
		assert_eq!(peer.get_neighbor_opinion(&(neighbor_id, epoch)), opinion);
	}

	#[test]
	fn should_add_and_remove_neghbours() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(1);
		let mut peer = Peer::new(kp, params);
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
		let params = ParamsKZG::<Bn256>::new(1);
		let mut peer = Peer::new(kp, params);

		let epoch = Epoch(0);
		for _ in 0..256 {
			let peer_id = PeerId::random();
			peer.add_neighbor(peer_id).unwrap();
			peer.set_score(peer_id, 5);
			let opinion = Opinion::new(epoch, 0.1, 0.1);
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

	#[test]
	fn should_add_neighbors_and_calculate_local_scores() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(1);
		let mut peer = Peer::new(kp, params);

		let epoch = Epoch(0);
		for _ in 0..256 {
			let peer_id = PeerId::random();
			peer.add_neighbor(peer_id).unwrap();
			peer.set_score(peer_id, 5);
			let opinion = Opinion::new(epoch, 0.1, 0.1);
			peer.cache_neighbor_opinion((peer_id, epoch), opinion);
		}

		let global_score = peer.calculate_global_trust_score(epoch);

		peer.calculate_local_opinions(epoch);

		for peer_id in peer.neighbors() {
			let opinion = peer.get_local_opinion(&(peer_id, epoch.next()));
			let score = peer.neighbor_scores.get(&peer_id).unwrap_or(&0);
			let normalized_score = peer.get_normalized_score(*score);
			let local_score = normalized_score * global_score;
			assert_eq!(opinion.product, local_score);
		}
	}
}
