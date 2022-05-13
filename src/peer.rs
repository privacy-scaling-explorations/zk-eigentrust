use crate::{epoch::Epoch, EigenError};
use libp2p::PeerId;
use std::collections::HashMap;

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

pub enum Rating {
	Positive,
	Negative,
}

pub struct Peer {
	neighbours: HashMap<PeerId, u32>,
	cached_neighbour_opinion: HashMap<(PeerId, Epoch), Opinion>,
	cached_local_opinion: HashMap<(PeerId, Epoch), Opinion>,
	global_scores: HashMap<Epoch, f64>,
	sum_of_scores: u32,
}

impl Peer {
	pub fn new(num_neighbours: usize) -> Self {
		let neighbours = HashMap::with_capacity(num_neighbours);
		// Sanity check:
		assert!(neighbours.len() == num_neighbours);
		assert!(neighbours.capacity() == num_neighbours);
		Peer {
			neighbours,
			cached_neighbour_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			global_scores: HashMap::new(),
			sum_of_scores: 0,
		}
	}

	pub fn add_neighbour(&mut self, peer_id: PeerId) -> Result<(), EigenError> {
		if self.neighbours.len() == self.neighbours.capacity() {
			return Err(EigenError::MaxNeighboursReached);
		}
		self.neighbours.insert(peer_id, 0);
		Ok(())
	}

	pub fn remove_neighbour(&mut self, peer_id: PeerId) {
		self.neighbours.remove(&peer_id);
	}

	pub fn iter_neighbours(
		&self,
		mut f: impl FnMut(PeerId) -> Result<(), EigenError>,
	) -> Result<(), EigenError> {
		for peer_id in self.neighbours.keys() {
			f(*peer_id)?;
		}

		Ok(())
	}

	pub fn calculate_local_opinions(&mut self, k: Epoch) -> Result<(), EigenError> {
		let mut global_score = 0.;

		self.iter_neighbours(|peer_id| {
			let opinion = self.get_neighbour_opinion(&(peer_id, k));
			global_score += opinion.get_product();
			Ok(())
		})?;

		let mut opinions = Vec::new();
		self.iter_neighbours(|peer_id| {
			let normalized_score = self.get_normalized_score(&peer_id)?;
			let product = global_score * normalized_score;
			let opinion = Opinion::new(k.next(), normalized_score, global_score, product);

			opinions.push((peer_id, opinion));
			Ok(())
		})?;

		for (peer_id, opinion) in opinions {
			self.cache_local_opinion((peer_id, opinion.get_epoch()), opinion);
		}
		self.global_scores.insert(k.next(), global_score);

		Ok(())
	}

	pub fn get_normalized_score(&self, peer_id: &PeerId) -> Result<f64, EigenError> {
		let score = self.neighbours.get(peer_id).map(|score| *score).ok_or(EigenError::InvalidPeerId)?;
		let sum = self.sum_of_scores;
		let f_raw_score = f64::from(score);
		let f_sum = f64::from(sum);
		Ok(f_raw_score / f_sum)
	}

	pub fn rate(&mut self, peer_id: &PeerId, rating: Rating) -> Result<(), EigenError> {
		let score = self.neighbours.get_mut(peer_id).ok_or(EigenError::InvalidPeerId)?;
		match rating {
			Rating::Positive => *score += 1,
			Rating::Negative => if *score > 0 {
				*score -= 1;
				self.sum_of_scores -= 1;
			},
		};

		Ok(())
	}

	pub fn get_global_score(&self, k: Epoch) -> f64 {
		*self.global_scores.get(&k).unwrap_or(&0.)
	}

	pub fn get_local_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self
			.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_local_opinion(&mut self, key: (PeerId, Epoch), response: Opinion) {
		self.cached_local_opinion.insert(key, response);
	}

	pub fn get_neighbour_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self
			.cached_neighbour_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_neighbour_opinion(&mut self, key: (PeerId, Epoch), response: Opinion) {
		self.cached_neighbour_opinion.insert(key, response);
	}
}
