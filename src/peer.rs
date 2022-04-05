//! The module for peer management. It contains the functionality for creating a
//! peer, adding local trust scores, and calculating the global trust score.

use ark_std::{collections::BTreeMap, fmt::Debug, hash::Hash, One, Zero};

/// Configuration trait for the Peer.
pub trait PeerConfig: Clone {
	/// Type for the Peer index.
	type Index: From<usize> + Eq + Hash + Clone + Ord + Debug;
}

/// Options for rating a transaction by a peer.
pub enum TransactionRating {
	/// Positive rating.
	Positive,
	/// Negative rating.
	Negative,
}

/// Peer structure.
#[derive(Clone, Debug)]
pub struct Peer<C: PeerConfig> {
	/// The unique identifier of the peer.
	index: C::Index,
	/// Transaction scores of the peer towards other peers.
	transaction_scores: BTreeMap<C::Index, u32>,
	/// Sum of all transaction scores.
	transaction_scores_sum: u32,
	/// Global trust score of the peer.
	global_trust_score: f64,
	/// Pre-trust score of the peer.
	pre_trust_scores: BTreeMap<C::Index, f64>,
	/// Did the peer converge?
	is_converged: bool,
}

impl<C: PeerConfig> Peer<C> {
	/// Create a new peer.
	pub fn new(index: C::Index, pre_trust_scores: BTreeMap<C::Index, f64>) -> Self {
		Self {
			index,
			transaction_scores: BTreeMap::new(),
			transaction_scores_sum: 0,
			global_trust_score: 0.,
			pre_trust_scores,
			is_converged: false,
		}
	}

	/// Function for mocking a transction rating.
	pub fn mock_rate_transaction(&mut self, i: C::Index, rating: TransactionRating) {
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
	pub fn heartbeat(&mut self, neighbors: &[Peer<C>], delta: f64, pre_trust_weight: f64) {
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

		println!("{:?}: {}", self.index, new_global_trust_score);

		// Converge if the difference between the new and old global trust score is less
		// than delta.
		let diff = (new_global_trust_score - self.global_trust_score).abs();
		if diff <= delta {
			self.is_converged = true;
		}

		self.global_trust_score = new_global_trust_score;
	}

	/// Check if the peer has converged.
	pub fn is_converged(&self) -> bool {
		self.is_converged
	}

	/// Get global trust score.
	pub fn get_global_trust_score(&self) -> f64 {
		self.global_trust_score
	}

	/// Get the transaction score for a peer.
	#[cfg(test)]
	pub fn get_transaction_scores(&self, index: &C::Index) -> u32 {
		*self.transaction_scores.get(index).unwrap_or(&0)
	}

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		*self.pre_trust_scores.get(&self.index).unwrap_or(&0.)
	}

	/// Get the index of the peer.
	pub fn get_index(&self) -> C::Index {
		self.index.clone()
	}

	/// Get the local trust score of the peer towards another peer.
	pub fn get_local_trust_score(&self, i: &C::Index) -> f64 {
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
		// If normalized_score is NaN, we should fall back to the trust score of the peer `i`.
		if normalized_score.is_nan() {
			normalized_score = *self.pre_trust_scores.get(i).unwrap_or(&0.);
		}
		
		normalized_score
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[derive(Clone, Debug, PartialEq)]
	struct TestConfig;
	impl PeerConfig for TestConfig {
		type Index = usize;
	}

	#[test]
	fn test_peer_new() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(0, 0.4);
		let peer = Peer::<TestConfig>::new(0, pre_trust_scores);
		assert_eq!(peer.get_index(), 0);
		assert_eq!(peer.get_global_trust_score(), 0.0);
		assert_eq!(peer.get_pre_trust_score(), 0.4);
	}

	#[test]
	fn local_trust_score_when_sum_is_zero() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(1, 0.4);
		let peer = Peer::<TestConfig>::new(0, pre_trust_scores);

		// Local trust towards peer `1` is the same as the pre-trust score.
		assert_eq!(peer.get_local_trust_score(&1), 0.4);
	}

	#[test]
	fn test_transactions() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(0, 0.4);
		let mut peer = Peer::<TestConfig>::new(0, pre_trust_scores);

		// 3 positive ratings to different peers
		peer.mock_rate_transaction(1, TransactionRating::Positive);
		peer.mock_rate_transaction(2, TransactionRating::Positive);

		// Everyone should have equal score
		assert_eq!(peer.get_local_trust_score(&1), 0.5);
		assert_eq!(peer.get_local_trust_score(&2), 0.5);

		assert_eq!(peer.get_transaction_scores(&1), 1);
	}

	#[test]
	fn global_trust_score_deterministic_calculation() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(0, 0.4);
		pre_trust_scores.insert(1, 0.4);
		pre_trust_scores.insert(2, 0.4);
		let mut peer0 = Peer::<TestConfig>::new(0, pre_trust_scores.clone());
		let mut peer1 = Peer::<TestConfig>::new(1, pre_trust_scores.clone());
		let mut peer2 = Peer::<TestConfig>::new(2, pre_trust_scores.clone());

		peer0.mock_rate_transaction(1, TransactionRating::Positive);
		peer0.mock_rate_transaction(2, TransactionRating::Positive);

		peer1.mock_rate_transaction(0, TransactionRating::Positive);
		peer1.mock_rate_transaction(2, TransactionRating::Positive);

		peer2.mock_rate_transaction(0, TransactionRating::Positive);
		peer2.mock_rate_transaction(1, TransactionRating::Positive);

		// ----------------- First round -----------------
		let delta = 0.00001;
		let pre_trust_weight = 0.4;
		let mut peers = [peer0.clone(), peer1.clone(), peer2.clone()];

		peer0.heartbeat(&peers, delta, pre_trust_weight);
		peer1.heartbeat(&peers, delta, pre_trust_weight);
		peer2.heartbeat(&peers, delta, pre_trust_weight);

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//             0.5                 *               0.0
			peers[1].get_local_trust_score(&0) * peers[1].get_global_trust_score() +
			// local score of peer2 towards peer0, times their global score
			//             0.5                 *               0.0
			peers[2].get_local_trust_score(&0) * peers[2].get_global_trust_score()
		;
		assert_eq!(peer1.get_local_trust_score(&0), 0.5);
		assert_eq!(sum_of_local_scores, 0.0);

		// (1.0 - 0.4) * 0.0 + 0.4 * 0.4 = 0.16
		let new_global_trust_score = (f64::one() - pre_trust_weight) * sum_of_local_scores
			+ pre_trust_weight * peer0.get_pre_trust_score();
		assert_eq!(peer0.get_global_trust_score(), new_global_trust_score);
		// Weird rounding error unfourtunately.
		assert_eq!(peer0.get_global_trust_score(), 0.16000000000000003);

		// ----------------- Second round -----------------
		peers = [peer0.clone(), peer1.clone(), peer2.clone()];

		peer0.heartbeat(&peers, delta, pre_trust_weight);
		peer1.heartbeat(&peers, delta, pre_trust_weight);
		peer2.heartbeat(&peers, delta, pre_trust_weight);

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//              0.5                *           0.16000000000000003
			peers[1].get_local_trust_score(&0) * peers[1].get_global_trust_score() +
			// local score of peer2 towards peer0, times their global score
			//              0.5                *            0.16000000000000003
			peers[2].get_local_trust_score(&0) * peers[2].get_global_trust_score()
		;
		assert_eq!(sum_of_local_scores, 0.16000000000000003);

		// (1.0 - 0.4) * 0.16 + 0.4 * 0.4 = 0.256
		let new_global_trust_score = (f64::one() - pre_trust_weight) * sum_of_local_scores
			+ pre_trust_weight * peer0.get_pre_trust_score();
		assert_eq!(peer0.get_global_trust_score(), new_global_trust_score);
		// Weird rounding error unfourtunately.
		assert_eq!(peer0.get_global_trust_score(), 0.25600000000000006);

		// ----------------- Third round -----------------
		peers = [peer0.clone(), peer1.clone(), peer2.clone()];

		peer0.heartbeat(&peers, delta, pre_trust_weight);
		peer1.heartbeat(&peers, delta, pre_trust_weight);
		peer2.heartbeat(&peers, delta, pre_trust_weight);

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//          0.5                    *           0.25600000000000006
			peers[1].get_local_trust_score(&0) * peers[1].get_global_trust_score() +
			// local score of peer2 towards peer0, times their global score
			//          0.5                    *           0.25600000000000006
			peers[2].get_local_trust_score(&0) * peers[2].get_global_trust_score()
		;
		assert_eq!(sum_of_local_scores, 0.25600000000000006);

		// (1.0 - 0.4) * 0.256 + 0.4 * 0.4 = 0.3136
		let new_global_trust_score = (f64::one() - pre_trust_weight) * sum_of_local_scores
			+ pre_trust_weight * peer0.get_pre_trust_score();

		assert_eq!(peer0.get_global_trust_score(), new_global_trust_score);
		// Weird rounding error unfourtunately.
		assert_eq!(peer0.get_global_trust_score(), 0.3136000000000001);
	}
}
