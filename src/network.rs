//! The module for the higher-level network functions.
//! It contains the functionality for creating peers, bootstrapping the
//! networks, and interactions between peers.

use crate::{
	peer::{Peer, PeerConfig, TransactionRating},
	EigenError,
};
use ark_std::{collections::BTreeMap, vec::Vec, Zero};
use rand::prelude::RngCore;

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
	) -> Result<Self, EigenError> {
		// TODO: Return proper errors.
		if pre_trust_scores.len() != C::SIZE {
			return Err(EigenError::InvalidPreTrustScores);
		}

		let pre_trust_score_map: BTreeMap<<C::Peer as PeerConfig>::Index, f64> = pre_trust_scores
			.into_iter()
			.enumerate()
			.map(|(i, score)| (i.into(), score))
			.collect();

		let mut peers = Vec::with_capacity(C::SIZE);
		// Creating initial peers.
		for x in 0..C::SIZE {
			let index = <C::Peer as PeerConfig>::Index::from(x);
			peers.push(Peer::new(index, pre_trust_score_map.clone()));
		}

		Ok(Self {
			peers,
			is_converged: false,
		})
	}

	/// Mock the transaction beetween peer `i` and `j`.
	pub fn mock_transaction(
		&mut self,
		i: usize,
		j: usize,
		rating: TransactionRating,
	) -> Result<(), EigenError> {
		let peer = self.peers.get_mut(i).ok_or(EigenError::PeerNotFound)?;

		let peer_index = <C::Peer as PeerConfig>::Index::from(j);
		peer.mock_rate_transaction(peer_index, rating);

		Ok(())
	}

	/// The main loop of the network. It iterates until the network converges
	/// or the maximum number of iterations is reached.
	pub fn converge<R: RngCore>(&mut self, _rng: &mut R) {
		let mut temp_peers = self.peers.clone();
		// We are shuffling the peers so that we can iterate over them in random order.
		// TODO: Explain why this is necessary.
		// temp_peers.shuffle(rng);

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
		let mut sum = f64::zero();
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

#[cfg(test)]
mod test {
	use super::*;
	use ark_std::One;
	use rand::thread_rng;

	#[derive(Clone, Copy, Debug)]
	struct Peer;
	impl PeerConfig for Peer {
		type Index = usize;
	}

	struct Network4Config;
	impl NetworkConfig for Network4Config {
		type Peer = Peer;

		const DELTA: f64 = 0.001;
		const MAX_ITERATIONS: usize = 1000;
		const PRETRUST_WEIGHT: f64 = 0.5;
		const SIZE: usize = 2;
	}

	#[test]
	fn bootstrapping_the_network() {
		let num_peers: usize = Network4Config::SIZE;
		let mut pre_trust_scores = vec![0.0; num_peers];
		pre_trust_scores[0] = 0.5;
		pre_trust_scores[1] = 0.5;

		let network = Network::<Network4Config>::bootstrap(pre_trust_scores).unwrap();

		assert_eq!(network.peers.len(), num_peers);
	}

	#[test]
	fn mock_transaction() {
		let num_peers: usize = Network4Config::SIZE;
		let mut pre_trust_scores = vec![0.0; num_peers];
		pre_trust_scores[0] = 0.5;
		pre_trust_scores[1] = 0.5;

		let mut network = Network::<Network4Config>::bootstrap(pre_trust_scores).unwrap();

		network
			.mock_transaction(0, 1, TransactionRating::Positive)
			.unwrap();

		assert_eq!(network.peers[0].get_transaction_scores(&1), 1);
	}

	#[test]
	fn network_converging_with_pre_trusted_peers() {
		let rng = &mut thread_rng();

		let num_peers: usize = Network4Config::SIZE;

		let default_score = 1. / (num_peers as f64);
		let pre_trust_scores = vec![default_score; num_peers];

		let mut network = Network::<Network4Config>::bootstrap(pre_trust_scores).unwrap();

		network
			.mock_transaction(0, 1, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 0, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 2, TransactionRating::Positive)
			.unwrap();

		// ------ Peer 0 ------
		let sum_of_local_scores_0 =
			// local score of peer1 towards peer0, times their global score
			//             0.5                         *               0.0
			network.peers[1].get_local_trust_score(&0) * network.peers[1].get_global_trust_score();
		assert_eq!(sum_of_local_scores_0, 0.0);

		// (1.0 - 0.5) * 0.0 + 0.5 * 0.5 = 0.25
		let new_global_trust_score_0 = (f64::one() - Network4Config::PRETRUST_WEIGHT)
			* sum_of_local_scores_0
			+ Network4Config::PRETRUST_WEIGHT * network.peers[0].get_pre_trust_score();

		// ------ Peer 1 ------
		let sum_of_local_scores_1 =
			// local score of peer0 towards peer1, times their global score
			//             1.0                         *               0.0
			network.peers[0].get_local_trust_score(&1) * network.peers[0].get_global_trust_score();
		assert_eq!(sum_of_local_scores_1, 0.0);

		// (1.0 - 0.5) * 0.0 + 0.5 * 0.5 = 0.25
		let new_global_trust_score_1 = (f64::one() - Network4Config::PRETRUST_WEIGHT)
			* sum_of_local_scores_1
			+ Network4Config::PRETRUST_WEIGHT * network.peers[1].get_pre_trust_score();

		// Converge the network.
		network.converge(rng);

		let peer0_score = network.peers[0].get_global_trust_score();
		assert_eq!(peer0_score, new_global_trust_score_0);
		assert_eq!(peer0_score, 0.25);

		let peer1_score = network.peers[1].get_global_trust_score();
		assert_eq!(peer1_score, new_global_trust_score_1);
		assert_eq!(peer1_score, 0.25);

		let global_trust_scores = network.get_global_trust_scores();
		assert_eq!(global_trust_scores[0], 0.5);
		assert_eq!(global_trust_scores[1], 0.5);
	}
}
