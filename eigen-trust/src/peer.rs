use crate::{epoch::Epoch, EigenError};
use libp2p::PeerId;
use std::collections::{hash_map::Keys, HashMap};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Opinion {
	k: Epoch,
	local_trust_score: f64,
	global_trust_score: f64,
	product: f64,
}

impl Opinion {
	pub fn new(k: Epoch, local_trust_score: f64, global_trust_score: f64, product: f64) -> Self {
		Self {
			k,
			local_trust_score,
			global_trust_score,
			product,
		}
	}

	pub fn empty(k: Epoch) -> Self {
		Self::new(k, 0.0, 0.0, 0.0)
	}

	pub fn get_epoch(&self) -> Epoch {
		self.k
	}

	pub fn get_local_trust_score(&self) -> f64 {
		self.local_trust_score
	}

	pub fn get_global_trust_score(&self) -> f64 {
		self.global_trust_score
	}

	pub fn get_product(&self) -> f64 {
		self.product
	}
}

pub struct Peer {
	neighbours: HashMap<PeerId, u32>,
	cached_neighbour_opinion: HashMap<(PeerId, Epoch), Opinion>,
	cached_local_opinion: HashMap<(PeerId, Epoch), Opinion>,
	pre_trust_score: f64,
	pre_trust_weight: f64,
	num_neighbours: usize,
}

impl Peer {
	pub fn new(num_neighbours: usize, pre_trust_score: f64, pre_trust_weight: f64) -> Self {
		let neighbours = HashMap::with_capacity(num_neighbours);
		Peer {
			neighbours,
			cached_neighbour_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			pre_trust_score,
			pre_trust_weight,
			num_neighbours,
		}
	}

	pub fn add_neighbour(&mut self, peer_id: PeerId, score: Option<u32>) -> Result<(), EigenError> {
		if self.neighbours.len() == self.num_neighbours {
			return Err(EigenError::MaxNeighboursReached);
		}
		let score = score.unwrap_or(0);
		self.neighbours.insert(peer_id, score);
		Ok(())
	}

	pub fn remove_neighbour(&mut self, peer_id: PeerId) {
		self.neighbours.remove(&peer_id);
	}

	pub fn neighbours(&self) -> Keys<PeerId, u32> {
		self.neighbours.keys()
	}

	pub fn set_score(&mut self, peer_id: PeerId, score: u32) {
		self.neighbours.insert(peer_id, score);
	}

	pub fn calculate_global_trust_score(&self, epoch: Epoch) -> f64 {
		let mut global_score = 0.;

		for peer_id in self.neighbours() {
			let opinion = self.get_neighbour_opinion(&(*peer_id, epoch));
			global_score += opinion.get_product();
		}
		global_score = (1. - self.pre_trust_weight) * global_score
			+ self.pre_trust_weight * self.pre_trust_score;

		global_score
	}

	pub fn calculate_local_opinions(&mut self, k: Epoch) {
		let global_score = self.calculate_global_trust_score(k);

		let mut opinions = Vec::new();
		for (peer_id, score) in self.neighbours.iter() {
			let normalized_score = self.get_normalized_score(*score);
			let product = global_score * normalized_score;
			let opinion = Opinion::new(k.next(), normalized_score, global_score, product);

			opinions.push((*peer_id, opinion));
		}

		for (peer_id, opinion) in opinions {
			self.cache_local_opinion((peer_id, opinion.get_epoch()), opinion);
		}
	}

	pub fn get_sum_of_scores(&self) -> u32 {
		let mut sum = 0;
		for score in self.neighbours.values() {
			sum += score;
		}
		sum
	}

	pub fn get_normalized_score(&self, score: u32) -> f64 {
		let sum = self.get_sum_of_scores();
		let f_raw_score = f64::from(score);
		let f_sum = f64::from(sum);
		f_raw_score / f_sum
	}

	pub fn get_local_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self
			.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_local_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_local_opinion.insert(key, opinion);
	}

	pub fn get_neighbour_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self
			.cached_neighbour_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_neighbour_opinion(&mut self, key: (PeerId, Epoch), opinion: Opinion) {
		self.cached_neighbour_opinion.insert(key, opinion);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_opinion() {
		let opinion = Opinion::new(Epoch(0), 0.5, 0.5, 0.5);
		assert_eq!(opinion.get_epoch(), Epoch(0));
		assert_eq!(opinion.get_global_trust_score(), 0.5);
		assert_eq!(opinion.get_local_trust_score(), 0.5);
		assert_eq!(opinion.get_product(), 0.5);
	}

	#[test]
	fn should_create_peer() {
		let peer = Peer::new(256, 0.5, 0.5);
		assert_eq!(peer.pre_trust_score, 0.5);
		assert_eq!(peer.pre_trust_weight, 0.5);
		assert_eq!(peer.get_sum_of_scores(), 0);
		assert_eq!(peer.num_neighbours, 256);
	}

	#[test]
	fn should_cache_local_and_global_opinion() {
		let pre_trust_score = 0.5;
		let pre_trust_weight = 0.5;
		let mut peer = Peer::new(256, pre_trust_score, pre_trust_weight);

		let epoch = Epoch(0);
		let neighbour_id = PeerId::random();
		let opinion = Opinion::new(epoch, 0.5, 0.5, 0.5);
		peer.cache_local_opinion((neighbour_id, epoch), opinion);
		peer.cache_neighbour_opinion((neighbour_id, epoch), opinion);

		assert_eq!(peer.get_local_opinion(&(neighbour_id, epoch)), opinion);
		assert_eq!(peer.get_neighbour_opinion(&(neighbour_id, epoch)), opinion);
	}

	#[test]
	fn should_add_and_remove_neghbours() {
		let mut peer = Peer::new(256, 0.5, 0.5);
		let neighbour_id = PeerId::random();

		peer.add_neighbour(neighbour_id, None).unwrap();
		let num_neighbours = peer.neighbours().len();
		assert_eq!(num_neighbours, 1);

		peer.remove_neighbour(neighbour_id);
		let num_neighbours = peer.neighbours().len();
		assert_eq!(num_neighbours, 0);
	}

	#[test]
	fn should_add_neighbours_and_calculate_global_score() {
		let pre_trust_score = 0.5;
		let pre_trust_weight = 0.5;
		let mut peer = Peer::new(256, pre_trust_score, pre_trust_weight);

		let epoch = Epoch(0);
		for _ in 0..256 {
			let peer_id = PeerId::random();
			peer.add_neighbour(peer_id, Some(5)).unwrap();
			let opinion = Opinion::new(epoch, 0.1, 0.1, 0.01);
			peer.cache_neighbour_opinion((peer_id, epoch), opinion);
		}

		let global_score = peer.calculate_global_trust_score(epoch);

		let mut true_global_score = 0.0;
		for _ in 0..256 {
			true_global_score += 0.01;
		}
		let boostrap_score =
			(1. - pre_trust_weight) * true_global_score + pre_trust_weight * pre_trust_score;

		assert_eq!(boostrap_score, global_score);
	}

	#[test]
	fn should_add_neighbours_and_calculate_local_scores() {
		let pre_trust_score = 0.5;
		let pre_trust_weight = 0.5;
		let mut peer = Peer::new(256, pre_trust_score, pre_trust_weight);

		let epoch = Epoch(0);
		for _ in 0..256 {
			let peer_id = PeerId::random();
			peer.add_neighbour(peer_id, Some(5)).unwrap();
			let opinion = Opinion::new(epoch, 0.1, 0.1, 0.01);
			peer.cache_neighbour_opinion((peer_id, epoch), opinion);
		}

		let global_score = peer.calculate_global_trust_score(epoch);

		peer.calculate_local_opinions(epoch);

		for (peer_id, score) in &peer.neighbours {
			let opinion = peer.get_local_opinion(&(*peer_id, epoch.next()));
			let normalized_score = peer.get_normalized_score(*score);
			let local_score = normalized_score * global_score;
			assert_eq!(opinion.get_product(), local_score);
		}
	}
}
