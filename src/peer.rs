//! The module for peer management. It contains the functionality for creating a
//! peer, adding local trust scores, and calculating the global trust score.

use crate::kd_tree::Key;
use ark_std::{collections::BTreeMap, fmt::Debug};

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
	/// Pre-trust score of the peer.
	pre_trust_scores: BTreeMap<Key, f64>,
	/// Managers of this peer.
	managers: Vec<Key>,
}

impl Peer {
	/// Create a new peer.
	pub fn new(index: Key, pre_trust_scores: BTreeMap<Key, f64>) -> Self {
		Self {
			index,
			transaction_scores: BTreeMap::new(),
			transaction_scores_sum: 0,
			pre_trust_scores,
			managers: Vec::new(),
		}
	}

	/// Set managers to the peer.
	pub fn set_managers(&mut self, managers: Vec<Key>) {
		self.managers = managers;
	}

	/// Function for mocking a transction rating.
	pub fn mock_rate_transaction(&mut self, i: &Key, rating: TransactionRating) {
		// Insert a 0 if entry does not exist.
		if !self.transaction_scores.contains_key(i) {
			self.transaction_scores.insert(*i, 0);
		}
		// Get the old score
		let score = self.transaction_scores[i];
		let sum = self.transaction_scores_sum;
		// Calculate the new score, but dont go below zero
		let (new_score, new_sum) = match rating {
			TransactionRating::Positive => (score + 1, sum + 1),
			TransactionRating::Negative if score > 0 => (score - 1, sum - 1),
			_ => (score, sum),
		};
		// Set the new score
		self.transaction_scores.insert(*i, new_score);
		// Update the sum
		self.transaction_scores_sum = new_sum;
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
		// If normalized_score is NaN, we should fall back to the pre-trust score of the
		// peer `i`.
		if normalized_score.is_nan() {
			// We could use either a pre-trusted value or 0.
			normalized_score = *self.pre_trust_scores.get(i).unwrap_or(&0.);
		}

		normalized_score
	}

	/// Get the managers of this peer.
	pub fn get_managers(&self) -> &Vec<Key> {
		&self.managers
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_new() {
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(Key::from(0), 0.4);
		let peer = Peer::new(Key::from(0), pre_trust_scores);

		let index = peer.get_index();
		let pre_trust_score = peer.get_pre_trust_score();
		assert_eq!(index, Key::from(0));
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
		peer.mock_rate_transaction(&one, TransactionRating::Positive);
		peer.mock_rate_transaction(&one, TransactionRating::Positive);
		peer.mock_rate_transaction(&one, TransactionRating::Negative);

		peer.mock_rate_transaction(&two, TransactionRating::Positive);
		peer.mock_rate_transaction(&two, TransactionRating::Positive);
		peer.mock_rate_transaction(&two, TransactionRating::Positive);

		// Everyone should have equal score
		assert_eq!(peer.get_local_trust_score(&one), 0.25);
		assert_eq!(peer.get_local_trust_score(&two), 0.75);

		assert_eq!(peer.get_transaction_scores(&one), 1);
		assert_eq!(peer.get_transaction_scores(&two), 3);
	}
}
