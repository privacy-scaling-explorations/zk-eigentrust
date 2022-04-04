//! The module for peer management. It contains the functionality for creating a
//! peer, adding local trust scores, and calculating the global trust score.

use ark_std::{collections::BTreeMap, fmt::Debug, hash::Hash, One, Zero};

/// Configuration trait for the Peer.
pub trait PeerConfig: Clone {
	/// Type for the Peer index.
	type Index: From<usize> + Eq + Hash + Clone + Ord;
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
	pre_trust_score: f64,
	/// Did the peer converge?
	is_converged: bool,
}

impl<C: PeerConfig> Peer<C> {
	/// Create a new peer.
	pub fn new(index: C::Index, global_trust_score: f64, pre_trust_score: f64) -> Self {
		Self {
			index,
			transaction_scores: BTreeMap::new(),
			transaction_scores_sum: 0,
			global_trust_score,
			pre_trust_score,
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
			let mut trust_score = neighbor_j.get_local_trust_score(&self.index);
			// If the trust score is NaN (due to division by 0, see
			// `get_local_trust_score`), we use the pre-trust score of that neighbor.
			if trust_score.is_nan() {
				trust_score = neighbor_j.get_pre_trust_score();
			}
			let neighbor_opinion = trust_score * neighbor_j.get_global_trust_score();
			new_global_trust_score += neighbor_opinion;
		}

		// (1 - a)*ti + a*p_i
		// The new global trust score (ti) is taken into account.
		// It is weighted by the `pre_trust_weight`, which dictates how seriously the
		// pre-trust score is taken.
		new_global_trust_score = (f64::one() - pre_trust_weight) * new_global_trust_score
			+ pre_trust_weight * self.pre_trust_score;

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

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		self.pre_trust_score
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
		f64::from(*score) / f64::from(sum)
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
		let mut peer = Peer::<TestConfig>::new(0, 0.0, 0.4);
		peer.mock_rate_transaction(1, TransactionRating::Positive);
		peer.mock_rate_transaction(2, TransactionRating::Positive);
		assert_eq!(peer.get_index(), 0);
		assert_eq!(peer.get_pre_trust_score(), 0.4);
		assert_eq!(peer.get_global_trust_score(), 0.0);
		assert_eq!(peer.get_local_trust_score(&1), 0.5);
	}
}
