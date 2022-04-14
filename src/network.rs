//! The module for the higher-level network functions.
//! It contains the functionality for creating peers, bootstrapping the
//! networks, and interactions between peers.

use crate::{
	kd_tree::{KdTree, Key},
	manager::Manager,
	peer::{Peer, TransactionRating},
	EigenError,
};
use ark_std::{collections::BTreeMap, marker::PhantomData, vec::Vec, Zero};
use rand::prelude::RngCore;

// use rand::prelude::SliceRandom;

/// The network configuration trait.
pub trait NetworkConfig {
	/// The minimum change in global score from last iteration.
	const DELTA: f64;
	/// A number of peers in the network.
	const SIZE: usize;
	/// Maximum iterations for the main loop to avoid infinite loop.
	const MAX_ITERATIONS: usize;
	/// Pre-trust weight - indicated how seriously the pre-trust scores are
	/// taken. Denoted as `a` in the [paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf) (Algorithm 3)
	const PRETRUST_WEIGHT: f64;
	/// Number of managers each peer gets.
	const NUM_MANAGERS: u64;
}

/// The struct contains all the peers and other metadata.
pub struct Network<C: NetworkConfig> {
	/// The peers in the network.
	peers: BTreeMap<Key, Peer>,
	/// Managers of the network.
	managers: BTreeMap<Key, Manager>,
	/// Tree containing all the managers distributed in 2d space.
	manager_tree: KdTree,
	/// Indicated whether the network has converged.
	is_converged: bool,
	_config: PhantomData<C>,
}

impl<C: NetworkConfig> Network<C> {
	/// Bootstraps the network. It creates the peers and initializes their
	/// local, global, and pre-trust scores.
	pub fn bootstrap(
		// Pre-trust scores of the peers. It is used in combination with the pre-trust weight.
		pre_trust_scores: Vec<f64>,
	) -> Result<Self, EigenError> {
		if pre_trust_scores.len() != C::SIZE {
			return Err(EigenError::InvalidPreTrustScores);
		}

		let pre_trust_score_map: BTreeMap<Key, f64> = pre_trust_scores
			.into_iter()
			.enumerate()
			.map(|(i, score)| (Key::from(i), score))
			.collect();

		let mut peers = BTreeMap::new();
		let mut managers = BTreeMap::new();
		let mut peer_keys = Vec::new();
		// Creating initial peers.
		for x in 0..C::SIZE {
			let index = Key::from(x);

			// Instantiate a peer
			let new_peer = Peer::new(index, pre_trust_score_map.clone());
			peers.insert(index, new_peer);

			// Instantiate a manager
			let new_manager = Manager::new(index, pre_trust_score_map.clone());
			managers.insert(index, new_manager);

			peer_keys.push(index);
		}

		// Instantiate the manager tree.
		let manager_tree =
			KdTree::new(peer_keys.clone()).map_err(|_| EigenError::InvalidManagerKeys)?;

		// We have to go through each peer and derive its managers from the key
		// Then, we have to assign those peers to the managers
		for key in peer_keys {
			let mut hash = key;
			for _ in 0..C::NUM_MANAGERS {
				hash = hash.hash();
				let manager_key = manager_tree
					.search(hash)
					.map_err(|_| EigenError::PeerNotFound)?;
				let manager = managers
					.get_mut(&manager_key)
					.ok_or(EigenError::PeerNotFound)?;

				// Add the children to the manager
				manager.add_child(key);
			}
		}

		Ok(Self {
			peers,
			managers,
			manager_tree,
			is_converged: false,
			_config: PhantomData,
		})
	}

	/// Mock the transaction beetween peer `i` and `j`.
	pub fn mock_transaction(
		&mut self,
		i: usize,
		j: usize,
		rating: TransactionRating,
	) -> Result<(), EigenError> {
		let peer_i_index = Key::from(i);
		let peer = self
			.peers
			.get_mut(&peer_i_index)
			.ok_or(EigenError::PeerNotFound)?;

		let peer_j_index = Key::from(j);
		peer.mock_rate_transaction(&peer_j_index, rating);

		Ok(())
	}

	/// The main loop of the network. It iterates until the network converges
	/// or the maximum number of iterations is reached.
	pub fn converge<R: RngCore>(&mut self, _rng: &mut R) -> Result<(), EigenError> {
		// Reset the whole network, so we can converge again.
		self.reset();

		let mut temp_managers = self.managers.clone();
		// We are shuffling the peers so that we can iterate over them in random order.
		// TODO: Research why this is necessary.
		// temp_peers.shuffle(rng);

		for _ in 0..C::MAX_ITERATIONS {
			// Loop over all the peers until all the peers converge.
			// In that case, the network is converged.
			let mut is_everyone_converged = true;
			for (_, manager) in temp_managers.iter_mut() {
				manager.heartbeat(
					&self.peers,
					&self.managers,
					&self.manager_tree,
					C::DELTA,
					C::PRETRUST_WEIGHT,
					C::NUM_MANAGERS,
				)?;

				is_everyone_converged = is_everyone_converged && manager.is_converged();
			}

			// We will break out of the loop if the network converges before the maximum
			// number of iterations
			if is_everyone_converged {
				self.is_converged = true;
				break;
			}
		}

		self.managers = temp_managers;

		Ok(())
	}

	/// Reset the network.
	pub fn reset(&mut self) {
		self.is_converged = false;
		// Reset all the managers
		for (_, manager) in self.managers.iter_mut() {
			manager.reset();
		}
	}

	/// Calculates the global trust score for each peer by normalizing the
	/// global trust scores.
	pub fn get_global_trust_scores(&self) -> Result<Vec<f64>, EigenError> {
		// Take any manager from the network.
		let manager1 = self
			.managers
			.values()
			.next()
			.ok_or(EigenError::PeerNotFound)?;
		let mut cached_global_scores: BTreeMap<Key, f64> = BTreeMap::new();

		// Calculate the global scores and cache them.
		// We do this by calling any manager in the network to calculate the global
		// scores for us.
		for (peer_index, _) in self.peers.iter() {
			let global_score = manager1.calculate_global_trust_score_for(
				peer_index,
				&self.managers,
				&self.manager_tree,
				C::NUM_MANAGERS,
			)?;
			cached_global_scores.insert(*peer_index, global_score);
		}
		// Calculate the sum.
		let mut sum = f64::zero();
		for (peer_index, _) in self.peers.iter() {
			let score = cached_global_scores
				.get(peer_index)
				.ok_or(EigenError::PeerNotFound)?;
			sum += score;
		}

		// Normalize the global trust scores.
		let mut ti_vec = Vec::new();
		for (peer_index, _) in self.peers.iter() {
			let cached_score = cached_global_scores
				.get(peer_index)
				.ok_or(EigenError::PeerNotFound)?;

			ti_vec.push(cached_score / sum);
		}

		Ok(ti_vec)
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

	struct TestNetworkConfig;
	impl NetworkConfig for TestNetworkConfig {
		const DELTA: f64 = 0.001;
		const MAX_ITERATIONS: usize = 1000;
		const NUM_MANAGERS: u64 = 1;
		const PRETRUST_WEIGHT: f64 = 0.5;
		const SIZE: usize = 2;
	}

	#[test]
	fn bootstrapping_the_network() {
		let num_peers: usize = TestNetworkConfig::SIZE;
		let mut pre_trust_scores = vec![0.0; num_peers];
		pre_trust_scores[0] = 0.5;
		pre_trust_scores[1] = 0.5;

		let network = Network::<TestNetworkConfig>::bootstrap(pre_trust_scores).unwrap();

		assert_eq!(network.peers.len(), num_peers);
	}

	#[test]
	fn should_not_mock_transaction_between_peers_with_invalid_index() {
		let num_peers: usize = TestNetworkConfig::SIZE;
		let pre_trust_scores = vec![0.0; num_peers];
		let mut network = Network::<TestNetworkConfig>::bootstrap(pre_trust_scores).unwrap();

		let res = network.mock_transaction(4, 1, TransactionRating::Positive);
		match res {
			Err(EigenError::PeerNotFound) => (),
			_ => panic!("Expected EigenError::PeerNotFound"),
		}
	}

	#[test]
	fn should_not_pass_invalid_pretrust_scores() {
		let num_peers: usize = TestNetworkConfig::SIZE - 1;
		let pre_trust_scores = vec![0.0; num_peers];

		let network = Network::<TestNetworkConfig>::bootstrap(pre_trust_scores);
		match network {
			Err(EigenError::InvalidPreTrustScores) => (),
			_ => panic!("Expected EigenError::InvalidPreTrustScores"),
		}
	}

	#[test]
	fn network_not_converging_without_pre_trusted_peers() {
		let rng = &mut thread_rng();

		let num_peers: usize = TestNetworkConfig::SIZE;

		let pre_trust_scores = vec![0.0; num_peers];

		let mut network = Network::<TestNetworkConfig>::bootstrap(pre_trust_scores).unwrap();

		network
			.mock_transaction(0, 1, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 0, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 2, TransactionRating::Positive)
			.unwrap();

		network.converge(rng).unwrap();

		assert!(network.is_converged());

		let key0 = Key::from(0);
		let key1 = Key::from(1);

		let peer0_trust_score = network.managers[&key0].get_global_trust_score_for(&key0);
		let peer1_trust_score = network.managers[&key0].get_global_trust_score_for(&key1);
		assert_eq!(peer0_trust_score, 0.0);
		assert_eq!(peer1_trust_score, 0.0);

		let global_trust_scores = network.get_global_trust_scores().unwrap();
		assert!(global_trust_scores[0].is_nan());
		assert!(global_trust_scores[1].is_nan());
	}

	#[test]
	fn network_converging_with_pre_trusted_peers() {
		let rng = &mut thread_rng();

		let num_peers: usize = TestNetworkConfig::SIZE;

		// 0.5
		let default_score = 1. / (num_peers as f64);
		let pre_trust_scores = vec![default_score; num_peers];

		let mut network = Network::<TestNetworkConfig>::bootstrap(pre_trust_scores).unwrap();

		network
			.mock_transaction(0, 1, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 0, TransactionRating::Positive)
			.unwrap();
		network
			.mock_transaction(1, 2, TransactionRating::Positive)
			.unwrap();

		let key0 = Key::from(0);
		let key1 = Key::from(1);

		// ------ Peer 0 ------
		let sum_of_local_scores_0 =
			// local score of peer1 towards peer0, times their global score
			//             0.5                         *               0.5
			network.peers[&key1].get_local_trust_score(&key0) * network.managers[&key0].get_global_trust_score_for(&key1);
		assert_eq!(sum_of_local_scores_0, 0.25);

		// (1.0 - 0.5) * 0.25 + 0.5 * 0.5 = 0.375
		let new_global_trust_score_0 = (f64::one() - TestNetworkConfig::PRETRUST_WEIGHT)
			* sum_of_local_scores_0
			+ TestNetworkConfig::PRETRUST_WEIGHT * network.peers[&key0].get_pre_trust_score();

		// ------ Peer 1 ------
		let sum_of_local_scores_1 =
			// local score of peer0 towards peer1, times their global score
			//             1.0                         *               0.5
			network.peers[&key0].get_local_trust_score(&key1) * network.managers[&key0].get_global_trust_score_for(&key0);
		assert_eq!(sum_of_local_scores_1, 0.5);

		// (1.0 - 0.5) * 0.5 + 0.5 * 0.5 = 0.5
		let new_global_trust_score_1 = (f64::one() - TestNetworkConfig::PRETRUST_WEIGHT)
			* sum_of_local_scores_1
			+ TestNetworkConfig::PRETRUST_WEIGHT * network.peers[&key1].get_pre_trust_score();

		// Converge the network.
		network.converge(rng).unwrap();

		let peer0_score = network.managers[&key0].get_global_trust_score_for(&key0);
		assert_eq!(peer0_score, new_global_trust_score_0);
		assert_eq!(peer0_score, 0.375);

		let peer1_score = network.managers[&key0].get_global_trust_score_for(&key1);
		assert_eq!(peer1_score, new_global_trust_score_1);
		assert_eq!(peer1_score, 0.5);

		let global_trust_scores = network.get_global_trust_scores().unwrap();
		assert_eq!(global_trust_scores[0], 0.42857142857142855);
		assert_eq!(global_trust_scores[1], 0.5714285714285714);
	}
}
