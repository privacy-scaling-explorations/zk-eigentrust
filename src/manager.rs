//! The module for peer management. It contains the functionality for creating a
//! peer, adding local trust scores, and calculating the global trust score.

use crate::{
	kd_tree::{KdTree, Key},
	peer::Peer,
	EigenError,
};
use ark_std::{collections::BTreeMap, fmt::Debug, One, Zero};

/// Peer structure.
#[derive(Clone, Debug)]
pub struct Manager {
	/// The unique identifier of the peer.
	index: Key,
	/// Global trust scores of the children.
	cached_global_trust_scores: BTreeMap<Key, f64>,
	/// Pre-trust score of the peer.
	pre_trust_scores: BTreeMap<Key, f64>,
	/// State of all children.
	children_states: BTreeMap<Key, bool>,
	/// Children of this manager.
	children: Vec<Key>
}

impl Manager {
	/// Create a new peer.
	pub fn new(index: Key, pre_trust_scores: BTreeMap<Key, f64>) -> Self {
		Self {
			index,
			// Initially, global trust score is equal to pre trusted score.
			cached_global_trust_scores: pre_trust_scores.clone(),
			pre_trust_scores,
			children_states: BTreeMap::new(),
			children: Vec::new(),
		}
	}

	/// Assign a child to this manager.
	pub fn add_child(&mut self, child: Key) {
		self.children.push(child);
	}

	/// Loop trought all the children and calculate their global trust score.
	pub fn heartbeat(
		&mut self,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		delta: f64,
		pre_trust_weight: f64,
		num_managers: u64,
	) -> Result<(), EigenError> {
		let children = self.children.clone();
		for peer in children {
			self.heartbeat_child(&peer, peers, managers, manager_tree, delta, pre_trust_weight, num_managers)?;
		}

		Ok(())
	}

	/// Calculate the global trust score.
	pub fn heartbeat_child(
		&mut self,
		index: &Key,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		delta: f64,
		pre_trust_weight: f64,
		num_managers: u64,
	) -> Result<(), EigenError> {
		let child_converged = self.children_states.get(index).unwrap_or(&false);
		if *child_converged {
			return Ok(());
		}

		let mut cached_global_scores: BTreeMap<Key, f64> = BTreeMap::new();

		// Calculate the global scores from previous iteration and cache them.
		for (peer_index, _) in peers.iter() {
			let global_score = self.calculate_global_trust_score_for(
				peer_index,
				managers,
				manager_tree,
				num_managers,
			)?;
			cached_global_scores.insert(*peer_index, global_score);
		}

		let mut new_global_trust_score = f64::zero();
		for (key_j, neighbor_j) in peers.iter() {
			// Skip if the neighbor is the same peer as child with `index`.
			if index == key_j {
				continue;
			}

			// Compute ti = `c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)`
			// We are going through each neighbor and taking their local trust
			// towards peer `i`, and multiplying it by that neighbor's global trust score.
			// This means that neighbors' opinion about peer i is weighted by their global
			// trust score. If a neighbor has a low trust score (is not trusted by the
			// network), their opinion is not taken seriously, compared to neighbors with a
			// high trust score.
			let trust_score = neighbor_j.get_local_trust_score(index);
			let global_score = cached_global_scores
				.get(key_j)
				.ok_or(EigenError::PeerNotFound)?;
			let neighbor_opinion = trust_score * global_score;
			new_global_trust_score += neighbor_opinion;
		}

		// (1 - a)*ti + a*p_i
		// The new global trust score (ti) is taken into account.
		// It is weighted by the `pre_trust_weight`, which dictates how seriously the
		// pre-trust score is taken.
		let peer_d = peers.get(index).ok_or(EigenError::PeerNotFound)?;
		new_global_trust_score = (f64::one() - pre_trust_weight) * new_global_trust_score
			+ pre_trust_weight * peer_d.get_pre_trust_score();

		// Converge if the difference between the new and old global trust score is less
		// than delta.
		let diff = (new_global_trust_score - self.get_global_trust_score_for(index)).abs();
		if diff <= delta {
			self.children_states.insert(*index, true);
		}

		self.cached_global_trust_scores
			.insert(*index, new_global_trust_score);

		Ok(())
	}

	/// Calculate the global trust score for `peer`. This is where we go to
	/// all the managers of `peer` and collect their cached global trust scores
	/// for this peer. We then do the majority vote, to settle on a particular
	/// score.
	pub fn calculate_global_trust_score_for(
		&self,
		index: &Key,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		num_managers: u64,
	) -> Result<f64, EigenError> {
		let mut scores: BTreeMap<[u8; 8], u64> = BTreeMap::new();
		// TODO: Should it be 2/3 majority or 1/2 majority?
		let majority = (num_managers / 3) * 2;

		let mut hash = *index;
		for _ in 0..num_managers {
			hash = hash.hash();
			let manager_key = manager_tree
				.search(hash)
				.map_err(|_| EigenError::PeerNotFound)?;
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

	/// Check if the global scores for children are converged.
	pub fn is_converged(&self) -> bool {
		for child in self.children.iter() {
			if !self.children_states.get(child).unwrap_or(&false) {
				return false;
			}
		}
		true
	}

	/// Reset all the children's states to false.
	pub fn reset(&mut self) {
		self.children_states = BTreeMap::new()
	}

	/// Get cached global trust score of the child peer.
	pub fn get_global_trust_score_for(&self, index: &Key) -> f64 {
		*self
			.cached_global_trust_scores
			.get(index)
			.unwrap_or(&f64::zero())
	}

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		*self.pre_trust_scores.get(&self.index).unwrap_or(&0.)
	}

	/// Get the index of the peer.
	pub fn get_index(&self) -> Key {
		self.index.clone()
	}
}
