//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

pub mod ivp;
pub mod pubkey;

use crate::{constants::MAX_NEIGHBORS, EigenError, Epoch};
use eigen_trust_circuit::halo2wrong::{
	curves::bn256::{Bn256, G1Affine},
	halo2::{plonk::ProvingKey, poly::kzg::commitment::ParamsKZG},
};
use ivp::Ivp;
use libp2p::{core::PublicKey, identity::Keypair, PeerId};
use pubkey::Pubkey;
use std::collections::HashMap;

/// The peer struct.
pub struct Peer {
	pub(crate) neighbors: [Option<PeerId>; MAX_NEIGHBORS],
	pubkeys_native: HashMap<PeerId, PublicKey>,
	pubkeys: HashMap<PeerId, Pubkey>,
	neighbor_scores: HashMap<PeerId, u32>,
	pub(crate) cached_neighbor_ivp: HashMap<(PeerId, Epoch, u32), Ivp>,
	pub(crate) cached_local_ivp: HashMap<(PeerId, Epoch, u32), Ivp>,
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
			cached_neighbor_ivp: HashMap::new(),
			cached_local_ivp: HashMap::new(),
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
		self.neighbors().iter().all(|&x| self.cached_neighbor_ivp.contains_key(&(x, epoch, k)))
	}

	/// Calculate the Ivp in the iteration 0
	pub fn calculate_initial_ivp(
		&mut self, peer_id: PeerId, epoch: Epoch,
	) -> Result<Ivp, EigenError> {
		if self.cached_local_ivp.contains_key(&(peer_id, epoch, 0)) {
			return Ok(self.cached_local_ivp.get(&(peer_id, epoch, 0)).cloned().unwrap());
		}
		let scores = [0.0; MAX_NEIGHBORS];
		let normalized_score = self.calculate_neighbour_score(peer_id);
		let pubkey = self.get_pub_key(peer_id).ok_or(EigenError::InvalidPubkey)?;
		let ivp = Ivp::generate(
			&self.keypair, &pubkey, epoch, 0, scores, normalized_score, &self.params,
			&self.proving_key,
		)?;
		// Cache the Ivp and return it
		self.cached_local_ivp.insert((peer_id, ivp.epoch, ivp.iter), ivp.clone());
		Ok(ivp)
	}

	/// Calculate the local trust score toward one neighbour in the specified
	/// epoch and generate zk proof of it.
	pub fn calculate_local_ivp(
		&mut self, peer_id: PeerId, epoch: Epoch, k: u32,
	) -> Result<Ivp, EigenError> {
		if self.cached_local_ivp.contains_key(&(peer_id, epoch, k + 1)) {
			return Ok(self.cached_local_ivp.get(&(peer_id, epoch, k + 1)).cloned().unwrap());
		}
		// Get a list of all scores
		let scores = self.get_neighbor_ivps_at(epoch, k)?;
		/// Normalized neighbour score
		let normalized_score = self.calculate_neighbour_score(peer_id);
		// Get the pubkey and generate the Ivp proof
		let pubkey = self.get_pub_key(peer_id).ok_or(EigenError::PubkeyNotFound)?;
		let ivp = Ivp::generate(
			&self.keypair,
			&pubkey,
			epoch,
			k + 1,
			scores,
			normalized_score,
			&self.params,
			&self.proving_key,
		)?;
		// Cache the Ivp and return it
		self.cached_local_ivp.insert((peer_id, ivp.epoch, ivp.iter), ivp.clone());
		Ok(ivp)
	}

	/// Function for calculating the normalized neighbour score
	pub fn calculate_neighbour_score(&self, peer_id: PeerId) -> f64 {
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
		normalized_score
	}

	/// Returns all of the Ivps of the neighbors in the specified iteration.
	pub fn get_neighbor_ivps_at(
		&self, epoch: Epoch, k: u32,
	) -> Result<[f64; MAX_NEIGHBORS], EigenError> {
		let mut scores: [f64; MAX_NEIGHBORS] = [0.; MAX_NEIGHBORS];
		// At other itrations we calculate it by taking the Ivps from previous
		// iterations
		for i in 0..scores.len() {
			let peer_id_opt = self.neighbors[i];
			if peer_id_opt.is_some() {
				let peer_id = peer_id_opt.unwrap();
				let ivp = self
					.cached_neighbor_ivp
					.get(&(peer_id, epoch, k))
					.ok_or(EigenError::IvpNotFound)?;
				scores[i] = ivp.op;
			}
		}
		Ok(scores)
	}

	/// Caches the neighbor Ivp towards us in specified epoch.
	pub fn cache_neighbor_ivp(
		&mut self, key: (PeerId, Epoch, u32), ivp: Ivp,
	) -> Result<(), EigenError> {
		if self.cached_neighbor_ivp.contains_key(&key) {
			return Ok(());
		}
		let vk = self.proving_key.get_vk();
		let pubkey_p = self.get_pub_key(key.0).ok_or(EigenError::PubkeyNotFound)?;
		let res = ivp.verify(&pubkey_p, &self.keypair, &self.params, vk)?;
		// Return an error if the proof is invalid
		if !res {
			log::debug!("Neighbour Ivp is not valid {:?}", key);
			return Err(EigenError::InvalidIvp);
		}
		// We add it only if its a valid proof
		self.cached_neighbor_ivp.insert(key, ivp);
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
	use crate::{
		constants::{BOOTSTRAP_PEERS, NUM_BOOTSTRAP_PEERS},
		keypair_from_sk_bytes,
	};
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
	fn should_cache_local_and_global_ivp() {
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

		let ivp = Ivp::empty(&params, &pk).unwrap();
		peer.cached_local_ivp.insert((neighbor_id, epoch, iter), ivp.clone());
		peer.cache_neighbor_ivp((neighbor_id, epoch, iter), ivp.clone()).unwrap();

		assert_eq!(
			peer.cached_local_ivp.get(&(neighbor_id, epoch, iter)).unwrap(),
			&ivp
		);
		assert_eq!(
			peer.cached_neighbor_ivp.get(&(neighbor_id, epoch, iter)).unwrap(),
			&ivp
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

		let iter = 0;
		let epoch = Epoch(3);
		for i in 0..BOOTSTRAP_PEERS.len() {
			let bytes = bs58::decode(BOOTSTRAP_PEERS[i]).into_vec().unwrap();
			let kp = keypair_from_sk_bytes(bytes).unwrap();
			let pubkey = Pubkey::from_keypair(&kp).unwrap();
			let peer_id = kp.public().to_peer_id();

			peer.add_neighbor(peer_id).unwrap();
			peer.identify_neighbor(peer_id, pubkey.clone());
			peer.set_score(peer_id, 5);

			// Create neighbour ivp.
			let mut op_ji = [0.; MAX_NEIGHBORS];
			op_ji[0] = 1.0;
			let c_v = 1.;
			let ivp =
				Ivp::generate(&kp, &local_pubkey, epoch, 0, op_ji, c_v, &params, &pk).unwrap();

			// Sanity check
			assert!(ivp.verify(&pubkey, &local_keypair, &params, &pk.get_vk()).unwrap());

			// Cache neighbour ivp.
			peer.cache_neighbor_ivp((peer_id, epoch, iter), ivp).unwrap();
		}

		for peer_id in peer.neighbors() {
			peer.calculate_local_ivp(peer_id, epoch, iter).unwrap();
		}

		let op_ji = peer.get_neighbor_ivps_at(epoch, iter).unwrap();
		let t_i = op_ji.iter().sum::<f64>();
		assert_eq!(t_i, 5.0);
		let c_v = t_i * 0.2;

		for peer_id in peer.neighbors() {
			let ivp = peer.cached_local_ivp.get(&(peer_id, epoch, iter + 1)).unwrap();
			assert_eq!(ivp.op, c_v);
		}
	}
}
