//! The module for peer management. It contains the functionality for creating a
//! manager and calculating the global trust scores for assigned children.

use crate::{kd_tree::Key, peer::Peer, EigenError};
use ark_std::{collections::BTreeMap, fmt::Debug, vec::Vec, One, Zero};

/// Manager structure.
#[derive(Clone, Debug)]
pub struct Manager {
	/// The unique identifier of the manager.
	index: Key,
	/// Global trust scores of the children.
	global_trust_scores: BTreeMap<Key, f64>,
	/// Pre-trust scores of the whole network.
	pre_trust_scores: BTreeMap<Key, f64>,
	/// State of all children.
	children_states: BTreeMap<Key, bool>,
	/// Children of this manager.
	children: Vec<Key>,
}

impl Manager {
	/// Create a new manager.
	pub fn new(index: Key, pre_trust_scores: BTreeMap<Key, f64>) -> Self {
		Self {
			index,
			// Initially, global trust score is equal to pre trusted score.
			global_trust_scores: pre_trust_scores.clone(),
			pre_trust_scores,
			children_states: BTreeMap::new(),
			children: Vec::new(),
		}
	}

	/// Add a child to the manager.
	pub fn add_child(&mut self, child: Key) {
		self.children.push(child);
	}

	/// Loop through all the children and calculate their global trust scores.
	pub fn heartbeat(
		&mut self,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		delta: f64,
		pre_trust_weight: f64,
	) -> Result<(), EigenError> {
		let children = self.children.clone();
		for peer in children {
			self.heartbeat_child(&peer, peers, managers, delta, pre_trust_weight)?;
		}

		Ok(())
	}

	/// Calculate the global trust score for chlid with id `index`.
	pub fn heartbeat_child(
		&mut self,
		index: &Key,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		delta: f64,
		pre_trust_weight: f64,
	) -> Result<(), EigenError> {
		let child_converged = self.children_states.get(index).unwrap_or(&false);
		if *child_converged {
			return Ok(());
		}

		let mut cached_global_scores: BTreeMap<Key, f64> = BTreeMap::new();

		// Calculate the global scores from the previous iteration and cache them.
		for (peer_index, peer) in peers.iter() {
			let global_score = Self::calculate_global_trust_score_for(peer, managers)?;
			cached_global_scores.insert(*peer_index, global_score);
		}

		let mut new_global_trust_score = f64::zero();
		for (key_j, neighbor_j) in peers.iter() {
			// Skip if the neighbor is the same as child.
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

		self.global_trust_scores
			.insert(*index, new_global_trust_score);

		Ok(())
	}

	/// Get the children for this manager.
	pub fn get_children(&self) -> Vec<Key> {
		self.children.clone()
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
		self.children_states.clear();
	}

	/// Get cached global trust score of the child peer.
	pub fn get_global_trust_score_for(&self, index: &Key) -> f64 {
		*self.global_trust_scores.get(index).unwrap_or(&0.)
	}

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		*self.pre_trust_scores.get(&self.index).unwrap_or(&0.)
	}

	/// Get the index of the peer.
	pub fn get_index(&self) -> Key {
		self.index.clone()
	}

	/// Calculate the global trust score for the peer with id `index`. This is
	/// where we go to all the managers of that peer and collect their cached
	/// global trust scores for this peer. We then do the majority vote, to
	/// settle on a particular score.
	pub fn calculate_global_trust_score_for(
		peer: &Peer,
		managers: &BTreeMap<Key, Manager>,
	) -> Result<f64, EigenError> {
		let mut scores: BTreeMap<[u8; 8], usize> = BTreeMap::new();
		let managers_for_peer = peer.get_managers();

		// TODO: Should it be 2/3 majority or 1/2 majority?
		let majority = (managers_for_peer.len() * 2) / 3;

		for manager_key in managers_for_peer {
			let manager = managers.get(&manager_key).ok_or(EigenError::PeerNotFound)?;
			let score = manager.get_global_trust_score_for(&peer.get_index());

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
}

#[cfg(test)]
mod test {
	use super::*;

	const DELTA: f64 = 0.00001;
	const PRE_TRUST_WEIGHT: f64 = 0.4;

	#[test]
	fn create_and_add_children() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);

		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.4);
		pre_trust_scores.insert(key1, 0.4);

		let peer0 = Peer::new(key0, pre_trust_scores.clone());
		let peer1 = Peer::new(key1, pre_trust_scores.clone());

		let mut peers = BTreeMap::new();
		peers.insert(key0, peer0);
		peers.insert(key1, peer1);

		let mut manager = Manager::new(key0, pre_trust_scores.clone());
		manager.add_child(key1);

		assert_eq!(manager.get_index(), key0);
		assert_eq!(manager.get_pre_trust_score(), 0.4);
		assert_eq!(manager.get_global_trust_score_for(&key1), 0.4);

		assert_eq!(manager.get_children(), vec![key1]);
		assert_eq!(manager.is_converged(), false);
	}

	#[test]
	fn vote_on_global_trust_score() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);
		let key2 = Key::from(2);

		let mut peer0 = Peer::new(key0, BTreeMap::new());
		peer0.set_managers(vec![key1, key2]);

		// Add two versions of pre-trust scores.
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.4);

		let mut other_pre_trust_scores = BTreeMap::new();
		other_pre_trust_scores.insert(key0, 0.3);

		// Test the case where the pre-trust score is the same for all managers.
		let manager1 = Manager::new(key1, pre_trust_scores.clone());
		let manager2 = Manager::new(key2, pre_trust_scores.clone());

		let mut managers = BTreeMap::new();
		managers.insert(key1, manager1.clone());
		managers.insert(key2, manager2.clone());

		let res = Manager::calculate_global_trust_score_for(&peer0, &managers).unwrap();
		assert_eq!(res, 0.4);

		// Test the case where the pre-trust score is different for some managers.
		let manager1 = Manager::new(key1, pre_trust_scores.clone());
		let manager2 = Manager::new(key2, other_pre_trust_scores.clone());

		let mut managers = BTreeMap::new();
		managers.insert(key1, manager1.clone());
		managers.insert(key2, manager2.clone());

		let res = Manager::calculate_global_trust_score_for(&peer0, &managers);
		assert_eq!(res.unwrap_err(), EigenError::GlobalTrustCalculationFailed);
	}

	#[test]
	fn should_converge() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);

		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.4);
		pre_trust_scores.insert(key1, 0.4);

		let mut peer0 = Peer::new(key0, pre_trust_scores.clone());
		let mut peer1 = Peer::new(key1, pre_trust_scores.clone());
		peer0.set_managers(vec![key1]);
		peer1.set_managers(vec![key0]);

		let mut peers = BTreeMap::new();
		peers.insert(key0, peer0);
		peers.insert(key1, peer1);

		let mut manager0 = Manager::new(key0, pre_trust_scores.clone());
		let mut manager1 = Manager::new(key1, pre_trust_scores.clone());
		manager0.add_child(key1);
		manager1.add_child(key0);

		let mut managers = BTreeMap::new();
		managers.insert(key0, manager0.clone());
		managers.insert(key1, manager1.clone());

		while !manager0.is_converged() {
			manager0
				.heartbeat(&peers, &managers, DELTA, PRE_TRUST_WEIGHT)
				.unwrap();
		}

		assert_eq!(manager0.is_converged(), true);
		let global_trust_score_before = manager0.get_global_trust_score_for(&key1);
		manager0
			.heartbeat(&peers, &managers, DELTA, PRE_TRUST_WEIGHT)
			.unwrap();
		let global_trust_score_after = manager0.get_global_trust_score_for(&key1);

		// The global trust score should not change after converging.
		assert_eq!(global_trust_score_before, global_trust_score_after);

		// Should be able to restart the manager.
		manager0.reset();
		assert_eq!(manager0.is_converged(), false);
	}

	#[test]
	fn global_trust_score_deterministic_calculation() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);

		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.4);
		pre_trust_scores.insert(key1, 0.4);

		let mut peer0 = Peer::new(key0, pre_trust_scores.clone());
		let mut peer1 = Peer::new(key1, pre_trust_scores.clone());
		peer0.set_managers(vec![key1]);
		peer1.set_managers(vec![key0]);

		let mut peers = BTreeMap::new();
		peers.insert(key0, peer0.clone());
		peers.insert(key1, peer1);

		let mut manager0 = Manager::new(key0, pre_trust_scores.clone());
		let mut manager1 = Manager::new(key1, pre_trust_scores.clone());
		manager0.add_child(key1);
		manager1.add_child(key0);

		let mut managers = BTreeMap::new();
		managers.insert(key0, manager0.clone());
		managers.insert(key1, manager1.clone());

		// Clone it before running the loop, so that we get deterministic results,
		// instead of operating on mutable objects.
		let managers_clone = managers.clone();

		// Running heartbeat.
		for (_, manager) in managers.iter_mut() {
			manager
				.heartbeat(&peers, &managers_clone, DELTA, PRE_TRUST_WEIGHT)
				.unwrap();
		}

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//             0.4                       *                       0.4
			peers[&key1].get_local_trust_score(&key0) * Manager::calculate_global_trust_score_for(&peer0, &managers_clone).unwrap();
		assert_eq!(peers[&key1].get_local_trust_score(&key0), 0.4);
		// Weird rounding error.
		assert_eq!(sum_of_local_scores, 0.16000000000000003);

		// (1.0 - 0.4) * 0.16 + 0.4 * 0.4 = 0.256
		let new_global_trust_score = (f64::one() - PRE_TRUST_WEIGHT) * sum_of_local_scores
			+ PRE_TRUST_WEIGHT * peers[&key0].get_pre_trust_score();
		assert_eq!(
			managers[&key1].get_global_trust_score_for(&key0),
			new_global_trust_score
		);
		// Weird rounding error unfortunately.
		assert_eq!(
			managers[&key1].get_global_trust_score_for(&key0),
			0.25600000000000006
		);
	}
}
