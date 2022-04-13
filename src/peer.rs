//! The module for peer management. It contains the functionality for creating a
//! peer, adding local trust scores, and calculating the global trust score.

use crate::{kd_tree::{KdTree, Key}, EigenError};
use ark_std::{collections::BTreeMap, fmt::Debug, One, Zero};

/// Options for rating a transaction by a peer.
pub enum TransactionRating {
	/// Positive rating.
	Positive,
	/// Negative rating.
	Negative,
}

/// Peer structure.
#[derive(Clone, Debug)]
pub struct Peer {
	/// The unique identifier of the peer.
	index: Key,
	/// Transaction scores of the peer towards other peers.
	transaction_scores: BTreeMap<Key, u32>,
	/// Sum of all transaction scores.
	transaction_scores_sum: u32,
	/// Global trust score of the peer.
	global_trust_score: f64,
	/// Global trust scores of the children.
	global_trust_scores: BTreeMap<Key, f64>,
	/// Pre-trust score of the peer.
	pre_trust_scores: BTreeMap<Key, f64>,
	/// Did the peer converge?
	is_converged: bool,
}

impl Peer {
	/// Create a new peer.
	pub fn new(index: Key, pre_trust_scores: BTreeMap<Key, f64>) -> Self {
		Self {
			index,
			transaction_scores: BTreeMap::new(),
			transaction_scores_sum: 0,
			global_trust_score: 0.,
			global_trust_scores: BTreeMap::new(),
			pre_trust_scores,
			is_converged: false,
		}
	}

	/// Function for mocking a transction rating.
	pub fn mock_rate_transaction(&mut self, i: Key, rating: TransactionRating) {
		// Insert a 0 if entry does not exist.
		if !self.transaction_scores.contains_key(&i) {
			self.transaction_scores.insert(i.clone(), 0);
		}
		// Get the old score
		let score = self.transaction_scores[&i];
		let sum = self.transaction_scores_sum;
		// Calculate the new score, but dont go below zero
		let (new_score, new_sum) = match rating {
			TransactionRating::Positive => (score + 1, sum + 1),
			TransactionRating::Negative if score > 0 => (score - 1, sum - 1),
			_ => (score, sum),
		};
		// Set the new score
		self.transaction_scores.insert(i, new_score);
		// Update the sum
		self.transaction_scores_sum = new_sum;
	}

	/// Calculate the global trust score.
	pub fn heartbeat(&mut self, neighbors: &[Peer], delta: f64, pre_trust_weight: f64) {
		if self.is_converged {
			return;
		}

		let mut new_global_trust_score = f64::zero();
		for neighbor_j in neighbors.iter() {
			// Skip if the neighbor is the same peer.
			if self.index == neighbor_j.get_index() {
				continue;
			}

			// Compute ti = `c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)`
			// We are going through each neighbor and taking their local trust
			// towards peer `i`, and multiplying it by that neighbor's global trust score.
			// This means that neighbors' opinion about peer i is weighted by their global
			// trust score. If a neighbor has a low trust score (is not trusted by the
			// network), their opinion is not taken seriously, compared to neighbors with a
			// high trust score.
			let trust_score = neighbor_j.get_local_trust_score(&self.index);
			let neighbor_opinion = trust_score * neighbor_j.get_global_trust_score();
			new_global_trust_score += neighbor_opinion;
		}

		// (1 - a)*ti + a*p_i
		// The new global trust score (ti) is taken into account.
		// It is weighted by the `pre_trust_weight`, which dictates how seriously the
		// pre-trust score is taken.
		new_global_trust_score = (f64::one() - pre_trust_weight) * new_global_trust_score
			+ pre_trust_weight * self.get_pre_trust_score();

		// Converge if the difference between the new and old global trust score is less
		// than delta.
		let diff = (new_global_trust_score - self.global_trust_score).abs();
		if diff <= delta {
			self.is_converged = true;
		}

		self.global_trust_score = new_global_trust_score;
	}

	/// Reset the peer state.
	pub fn reset(&mut self) {
		self.is_converged = false;
	}

	/// Check if the peer has converged.
	pub fn is_converged(&self) -> bool {
		self.is_converged
	}

	/// Get global trust score.
	pub fn get_global_trust_score(&self) -> f64 {
		// If the peer's global trust score is zero we want to use their pre-trusted
		// score. This helps with more fair converging when bootstrapping the network.
		// NOTE: This is not in the original [paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf)
		if self.global_trust_score.is_zero() {
			return self.get_pre_trust_score();
		}
		self.global_trust_score
	}

	/// Get cached global trust score of the child peer.
	pub fn get_global_trust_score_for(&self, index: &Key) -> f64 {
		*self.global_trust_scores.get(index).unwrap_or(&f64::zero())
	}

	/// Calculate the global trust score for `peer`. This is where we go to
	/// all the managers of `peer` and collect their global trust scores.
	/// We then do the majority vote, to settle on a particular score.
	pub fn calculate_global_trust_score_for(
		&self,
		index: &Key,
		managers: &BTreeMap<Key, Peer>,
		manager_tree: KdTree,
		num_managers: usize,
	) -> Result<f64, EigenError> {
		let mut scores: BTreeMap<[u8; 8], u64> = BTreeMap::new();
		// Should it be 2/3 majority or 1/2 majority?
		let majority = (u64::from_be_bytes(num_managers.to_be_bytes()) / 3) * 2;

		for _ in 0..num_managers {
			let hash = index.hash();
			let manager_key = manager_tree.search(hash).map_err(|_| EigenError::PeerNotFound)?;
			let manager = managers.get(&manager_key).ok_or(EigenError::PeerNotFound)?;
			let score = manager.get_global_trust_score_for(index);

			let score_bytes = score.to_be_bytes();
			
			let count = scores.entry(score_bytes).or_insert(0);
			*count += 1;

			if *count > majority {
				return Ok(score);
			}
		}

		// We reached the end of the vote without finding a majority.
		Err(EigenError::GlobalTrustCalculationFailed)
	}

	/// Get the transaction score for a peer.
	#[cfg(test)]
	pub fn get_transaction_scores(&self, index: &Key) -> u32 {
		*self.transaction_scores.get(index).unwrap_or(&0)
	}

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		*self.pre_trust_scores.get(&self.index).unwrap_or(&0.)
	}

	/// Get the index of the peer.
	pub fn get_index(&self) -> Key {
		self.index.clone()
	}

	/// Get the local trust score of the peer towards another peer.
	pub fn get_local_trust_score(&self, i: &Key) -> f64 {
		// Take the score or default to 0.
		let score = self.transaction_scores.get(i).unwrap_or(&0);
		// Take the sum
		let sum = self.transaction_scores_sum;
		// Calculate normalized score
		// NOTE:
		// If a peer didn't have any transactions towards other peers,
		// the sum will be zero, which will cause a division by zero.
		// Resulting in NaN.
		let mut normalized_score = f64::from(*score) / f64::from(sum);
		// If normalized_score is NaN, we should fall back to the trust score of the
		// peer `i`.
		if normalized_score.is_nan() {
			// We could use either a pre-trusted value or 0.
			normalized_score = *self.pre_trust_scores.get(i).unwrap_or(&0.);
		}

		normalized_score
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_peer_new() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(Key::from(0), 0.4);
		let peer = Peer::new(Key::from(0), pre_trust_scores);

		let index = peer.get_index();
		let global_trust_score = peer.get_global_trust_score();
		let pre_trust_score = peer.get_pre_trust_score();
		assert_eq!(index, Key::from(0));
		assert_eq!(global_trust_score, 0.4);
		assert_eq!(pre_trust_score, 0.4);
	}

	#[test]
	fn local_trust_score_when_sum_is_zero() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(Key::from(1), 0.4);
		let peer = Peer::new(Key::from(0), pre_trust_scores);

		// Local trust towards peer `1` is the same as the pre-trust score.
		assert_eq!(peer.get_local_trust_score(&Key::from(1)), 0.4);
	}

	#[test]
	fn test_transactions() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(Key::from(0), 0.4);
		let mut peer = Peer::new(Key::from(0), pre_trust_scores);

		// 3 positive ratings to different peers
		let one = Key::from(1);
		let two = Key::from(2);
		peer.mock_rate_transaction(one, TransactionRating::Positive);
		peer.mock_rate_transaction(one, TransactionRating::Positive);
		peer.mock_rate_transaction(one, TransactionRating::Negative);
		peer.mock_rate_transaction(two, TransactionRating::Positive);

		// Everyone should have equal score
		assert_eq!(peer.get_local_trust_score(&one), 0.5);
		assert_eq!(peer.get_local_trust_score(&two), 0.5);

		assert_eq!(peer.get_transaction_scores(&one), 1);
	}

	#[test]
	fn peer_should_converge() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(Key::from(0), 0.4);
		pre_trust_scores.insert(Key::from(0), 0.4);
		pre_trust_scores.insert(Key::from(0), 0.4);
		let mut peer0 = Peer::new(Key::from(0), pre_trust_scores.clone());
		let mut peer1 = Peer::new(Key::from(1), pre_trust_scores.clone());
		let mut peer2 = Peer::new(Key::from(2), pre_trust_scores.clone());

		peer0.mock_rate_transaction(Key::from(1), TransactionRating::Positive);
		peer0.mock_rate_transaction(Key::from(2), TransactionRating::Positive);

		peer1.mock_rate_transaction(Key::from(0), TransactionRating::Positive);
		peer1.mock_rate_transaction(Key::from(2), TransactionRating::Positive);

		peer2.mock_rate_transaction(Key::from(0), TransactionRating::Positive);
		peer2.mock_rate_transaction(Key::from(1), TransactionRating::Positive);

		let delta = 0.00001;
		let pre_trust_weight = 0.4;
		let peers = [peer0.clone(), peer1.clone(), peer2.clone()];

		while !peer0.is_converged() {
			peer0.heartbeat(&peers, delta, pre_trust_weight);
			peer1.heartbeat(&peers, delta, pre_trust_weight);
			peer2.heartbeat(&peers, delta, pre_trust_weight);
		}

		let is_converged = peer0.is_converged();
		assert!(is_converged);

		let global_score_before = peer0.get_global_trust_score();
		peer0.heartbeat(&peers, delta, pre_trust_weight);
		let global_score_after = peer0.get_global_trust_score();
		// The global trust score should not change after converging.
		assert_eq!(global_score_before, global_score_after);
	}

	#[test]
	fn global_trust_score_deterministic_calculation() {
		let mut pre_trust_scores = BTreeMap::new();
		let default_score = 0.25;
		pre_trust_scores.insert(Key::from(0), default_score);
		pre_trust_scores.insert(Key::from(1), default_score);
		pre_trust_scores.insert(Key::from(2), default_score);
		let mut peer0 = Peer::new(Key::from(0), pre_trust_scores.clone());
		let mut peer1 = Peer::new(Key::from(1), pre_trust_scores.clone());
		let mut peer2 = Peer::new(Key::from(2), pre_trust_scores.clone());

		peer0.mock_rate_transaction(Key::from(1), TransactionRating::Positive);
		peer0.mock_rate_transaction(Key::from(2), TransactionRating::Positive);

		peer1.mock_rate_transaction(Key::from(0), TransactionRating::Positive);
		peer1.mock_rate_transaction(Key::from(2), TransactionRating::Positive);

		peer2.mock_rate_transaction(Key::from(0), TransactionRating::Positive);
		peer2.mock_rate_transaction(Key::from(1), TransactionRating::Positive);

		let delta = 0.00001;
		let pre_trust_weight = 0.4;
		let peers = [peer0.clone(), peer1.clone(), peer2.clone()];

		peer0.heartbeat(&peers, delta, pre_trust_weight);
		peer1.heartbeat(&peers, delta, pre_trust_weight);
		peer2.heartbeat(&peers, delta, pre_trust_weight);

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//             0.5                 *               0.25
			peers[1].get_local_trust_score(&Key::from(0)) * peers[1].get_global_trust_score() +
			// local score of peer2 towards peer0, times their global score
			//             0.5                 *               0.25
			peers[2].get_local_trust_score(&Key::from(0)) * peers[2].get_global_trust_score()
		;
		assert_eq!(peer1.get_local_trust_score(&Key::from(0)), 0.5);
		assert_eq!(sum_of_local_scores, 0.25);

		// (1.0 - 0.4) * 0.25 + 0.4 * 0.25 = 0.25
		let new_global_trust_score = (f64::one() - pre_trust_weight) * sum_of_local_scores
			+ pre_trust_weight * peer0.get_pre_trust_score();
		assert_eq!(peer0.get_global_trust_score(), new_global_trust_score);
		// Weird rounding error unfourtunately.
		assert_eq!(peer0.get_global_trust_score(), 0.25);
	}
}
