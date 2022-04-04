//! The module for the higher-level network functions.
//! It contains the functionality for creating peers, bootstrapping the
//! networks, and interactions between peers.

use crate::{
	peer::{PeerConfig, Peer},
	EigenError,
};
use ark_std::vec::Vec;
use rand::prelude::{RngCore, SliceRandom};

/// The network configuration trait.
pub trait NetworkConfig {
	/// Configuration trait for the peer.
	type Peer: PeerConfig;
	/// The minimum change in global score from last iteration.
	const DELTA: f64;
	/// A number of peers in the network.
	const SIZE: usize;
	/// Maximum iterations for the main loop to avoid infinite loop.
	const MAX_ITERATIONS: usize;
	/// Pre-trust weight - indicated how seriously the pre-trust scores are
	/// taken. Denoted as `a` in the [paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf) (Algorithm 3)
	const PRETRUST_WEIGHT: f64;
}

/// The struct contains all the peers and other metadata.
pub struct Network<C: NetworkConfig> {
	/// The peers in the network.
	peers: Vec<Peer<C::Peer>>,
	/// Indicated whether the network has converged.
	is_converged: bool,
}

impl<C: NetworkConfig> Network<C> {
	/// Bootstraps the network. It creates the peers and initializes their
	/// local, global, and pre-trust scores.
	pub fn bootstrap(
		// Pre-trust scores of the peers. It is used in combination with the pre-trust weight.
		pre_trust_scores: Vec<f64>,
		// Initial global trust scores for each peer in the network.
		global_trust_scores: Vec<f64>,
		// Initial local trust scores for each peer in the network towards other peers.
		local_trust_scores: Vec<Vec<f64>>,
	) -> Result<Self, EigenError> {
		// TODO: Return proper errors.
		if pre_trust_scores.len() != C::SIZE {
			return Err(EigenError::InvalidPreTrustScores);
		}
		if global_trust_scores.len() != C::SIZE {
			return Err(EigenError::InvalidGlobalTrustScores);
		}
		if local_trust_scores.len() != C::SIZE {
			return Err(EigenError::InvalidLocalTrustScores);
		}

		let mut peers = Vec::with_capacity(C::SIZE);
		// Creating initial peers.
		for x in 0..C::SIZE {
			let index = <C::Peer as PeerConfig>::Index::from(x);
			peers.push(Peer::new(
				index,
				global_trust_scores[x as usize],
				pre_trust_scores[x as usize],
			));
		}

		// Initializing the local trust scores for peer `i` towards peer `j`.
		for (i, c_i) in local_trust_scores.iter().enumerate() {
			if c_i.len() != C::SIZE {
				return Err(EigenError::InvalidLocalTrustScores);
			}

			for (j, c_ij) in c_i.iter().enumerate() {
				if i == j {
					continue;
				}

				let index = peers[j].get_index();
				peers[i].add_neighbor(index, *c_ij);
			}
		}

		Ok(Self {
			peers,
			is_converged: false,
		})
	}

	/// The main loop of the network. It iterates until the network converges
	/// or the maximum number of iterations is reached.
	pub fn converge<R: RngCore>(&mut self, rng: &mut R) {
		let mut temp_peers = self.peers.clone();
		// We are shuffling the peers so that we can iterate over them in random order.
		// TODO: Explain why this is necessary.
		temp_peers.shuffle(rng);

		for _ in 0..C::MAX_ITERATIONS {
			// Loop over all the peers until all the peers converge.
			// In that case, the network is converged.
			let mut is_everyone_converged = true;
			for peer in temp_peers.iter_mut() {
				peer.heartbeat(&self.peers, C::DELTA, C::PRETRUST_WEIGHT);
				is_everyone_converged = is_everyone_converged && peer.is_converged();
			}

			// We will break out of the loop if the network converges before the maximum
			// number of iterations.
			if is_everyone_converged {
				self.is_converged = true;
				break;
			}
		}

		self.peers = temp_peers;
	}

	/// Calculates the global trust score for each peer by normalizing the
	/// global trust scores.
	pub fn get_global_trust_scores(&self) -> Vec<f64> {
		// Calculate the sum.
		let mut sum = 0.;
		for peer in self.peers.iter() {
			sum += peer.get_global_trust_score();
		}

		// Normalize the global trust scores.
		let mut ti_vec = Vec::new();
		for peer in self.peers.iter() {
			ti_vec.push(peer.get_global_trust_score() / sum);
		}

		ti_vec
	}

	/// Check whether the network converged.
	pub fn is_converged(&self) -> bool {
		self.is_converged
	}
}
