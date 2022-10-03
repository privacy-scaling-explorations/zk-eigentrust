//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

pub mod opinion;
pub mod pubkey;

use crate::{constants::MAX_NEIGHBORS, EigenError, Epoch};
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
	pub(crate) cached_neighbor_opinion: HashMap<(PeerId, Epoch, u32), Opinion>,
	pub(crate) cached_local_opinion: HashMap<(PeerId, Epoch, u32), Opinion>,
	keypair: Keypair,
	pub(crate) pubkey: Pubkey,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Peer {
	/// Creates a new peer.
	pub fn new(
		keypair: Keypair, params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		Ok(Peer {
			neighbors: [None; MAX_NEIGHBORS],
			pubkeys_native: HashMap::new(),
			pubkeys: HashMap::new(),
			neighbor_scores: HashMap::new(),
			cached_neighbor_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			pubkey: Pubkey::from_keypair(&keypair)?,
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

	/// Checks whether we received the proofs from all neighbours
	pub fn has_all_neighbour_proofs_at(&self, epoch: Epoch, k: u32) -> bool {
		self.neighbors()
			.iter()
			.all(|&x| self.cached_neighbor_opinion.contains_key(&(x, epoch, k)))
	}

	/// Calculate the local trust score toward one neighbour in the specified
	/// epoch and generate zk proof of it.
	pub fn calculate_local_opinion(
		&mut self, peer_id: PeerId, epoch: Epoch, k: u32,
	) -> Result<Opinion, EigenError> {
		if self.cached_local_opinion.contains_key(&(peer_id, epoch, k)) {
			return Ok(self.cached_local_opinion.get(&(peer_id, epoch, k)).cloned().unwrap());
		}
		// Get a list of all scores
		let scores = self.get_neighbor_opinions_at(epoch, k)?;
		// Calculate the normalized score
		let score = self.neighbor_scores.get(&peer_id).unwrap_or(&0);
		let mut sum = 0.;
		for n in self.neighbors() {
			let s = self.neighbor_scores.get(&n).unwrap_or(&0);
			sum += f64::from(*s);
		}
		let f_raw_score = f64::from(*score);
		let f_sum = f64::from(sum);
		let normalized_score = f_raw_score / f_sum;
		let normalized_score = if normalized_score.is_nan() { 0. } else { normalized_score };
		// Get the pubkey and generate the opinion proof
		let pubkey = self.get_pub_key(peer_id).ok_or(EigenError::InvalidPubkey)?;
		let opinion = Opinion::generate(
			&self.keypair,
			&pubkey,
			epoch,
			k + 1,
			scores,
			normalized_score,
			&self.params,
			&self.proving_key,
		)?;
		// Cache the opinion and return it
		self.cached_local_opinion.insert((peer_id, opinion.epoch, opinion.iter), opinion.clone());
		Ok(opinion)
	}

	/// Returns all of the opinions of the neighbors in the specified iteration.
	pub fn get_neighbor_opinions_at(
		&self, epoch: Epoch, k: u32,
	) -> Result<[f64; MAX_NEIGHBORS], EigenError> {
		let mut scores: [f64; MAX_NEIGHBORS] = [0.; MAX_NEIGHBORS];
		// At iteration 0, return zeros
		if k == 0 {
			return Ok(scores);
		}
		// At other itrations we calculate it by taking the opinions from previous
		// iterations
		for i in 0..scores.len() {
			let peer_id_opt = self.neighbors[i];
			if peer_id_opt.is_some() {
				let peer_id = peer_id_opt.unwrap();
				let opinion = self
					.cached_neighbor_opinion
					.get(&(peer_id, epoch, k))
					.ok_or(EigenError::OpinionNotFound)?;
				scores[i] = opinion.op;
			}
		}
		Ok(scores)
	}

	/// Caches the neighbor opinion towards us in specified epoch.
	pub fn cache_neighbor_opinion(
		&mut self, key: (PeerId, Epoch, u32), opinion: Opinion,
	) -> Result<(), EigenError> {
		let vk = self.proving_key.get_vk();
		let pubkey_p = self.get_pub_key(key.0).ok_or(EigenError::PubkeyNotFound)?;
		let res = opinion.verify(&pubkey_p, &self.keypair, &self.params, vk)?;
		// Return an error if the proof is invalid
		if !res {
			log::debug!("Neighbour opinion is not valid {:?}", key);
			return Err(EigenError::InvalidOpinion);
		}
		// We add it only if its a valid proof
		self.cached_neighbor_opinion.insert(key, opinion);
		Ok(())
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
		params::poseidon_bn254_5x5::Params,
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
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let peer = Peer::new(kp, params, pk);

		assert!(peer.is_ok());
	}

	#[test]
	fn should_cache_local_and_global_opinion() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let mut peer = Peer::new(kp, params.clone(), pk.clone()).unwrap();

		let iter = 0;
		let epoch = Epoch(0);
		let neighbor_id = PeerId::random();

		let neighbour_kp = Keypair::generate_secp256k1();
		let pubkey_native = neighbour_kp.public();
		let pubkey = Pubkey::from_keypair(&neighbour_kp).unwrap();
		peer.identify_neighbor_native(neighbor_id, pubkey_native);
		peer.identify_neighbor(neighbor_id, pubkey);

		let opinion = Opinion::empty(&params, &pk).unwrap();
		peer.cached_local_opinion.insert((neighbor_id, epoch, iter), opinion.clone());
		peer.cache_neighbor_opinion((neighbor_id, epoch, iter), opinion.clone()).unwrap();

		assert_eq!(
			peer.cached_local_opinion.get(&(neighbor_id, epoch, iter)).unwrap(),
			&opinion
		);
		assert_eq!(
			peer.cached_neighbor_opinion.get(&(neighbor_id, epoch, iter)).unwrap(),
			&opinion
		);
	}

	#[test]
	fn should_add_and_remove_neghbours() {
		let kp = Keypair::generate_secp256k1();
		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
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

	#[test]
	fn should_add_neighbors_and_calculate_global_score() {
		let rng = &mut thread_rng();
		let local_keypair = Keypair::generate_secp256k1();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let params = ParamsKZG::<Bn256>::new(9);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let mut peer = Peer::new(local_keypair.clone(), params.clone(), pk.clone()).unwrap();

		let iter = 3;
		let epoch = Epoch(3);
		for _ in 0..4 {
			let kp = Keypair::generate_secp256k1();
			let pubkey = Pubkey::from_keypair(&kp).unwrap();
			let peer_id = kp.public().to_peer_id();

			peer.add_neighbor(peer_id).unwrap();
			peer.identify_neighbor(peer_id, pubkey.clone());
			peer.set_score(peer_id, 5);

			// Create neighbor opinion.
			let mut op_ji = [0.; MAX_NEIGHBORS];
			op_ji[0] = 0.1;
			let c_v = 1.;
			let opinion = Opinion::generate(
				&kp,
				&local_pubkey,
				epoch,
				iter - 1,
				op_ji,
				c_v,
				&params,
				&pk,
			)
			.unwrap();

			// Sanity check
			assert!(opinion.verify(&pubkey, &local_keypair, &params, &pk.get_vk()).unwrap());

			// Cache neighbor opinion.
			peer.cache_neighbor_opinion((peer_id, epoch, iter - 1), opinion).unwrap();
		}

		for peer_id in peer.neighbors() {
			peer.calculate_local_opinion(peer_id, epoch, iter).unwrap();
		}

		let op_ji = peer.get_neighbor_opinions_at(epoch, iter).unwrap();
		let t_i = op_ji.iter().sum::<f64>();
		assert_eq!(t_i, 0.4);
		let c_v = t_i * 0.25;

		for peer_id in peer.neighbors() {
			let opinion = peer.cached_local_opinion.get(&(peer_id, epoch, iter)).unwrap();
			assert_eq!(opinion.op, c_v);
		}
	}
}
