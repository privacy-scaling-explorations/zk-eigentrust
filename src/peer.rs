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

#[derive(Clone, Copy, Debug)]
pub struct Neighbour {
	peer_id: PeerId,
	score: u32,
}

impl Neighbour {
	pub fn new(peer_id: PeerId) -> Self {
		Self { peer_id, score: 0 }
	}

	pub fn get_peer_id(&self) -> PeerId {
		self.peer_id
	}

	pub fn get_normalized_score(&self, sum: u32) -> f64 {
		let f_raw_score = f64::from(self.score);
		let f_sum = f64::from(sum);
		f_raw_score / f_sum
	}
}

pub struct Peer {
	neighbours: Vec<Option<Neighbour>>,
	cached_neighbour_opinion: HashMap<(PeerId, Epoch), Opinion>,
	cached_local_opinion: HashMap<(PeerId, Epoch), Opinion>,
	global_scores: HashMap<Epoch, f64>,
}

impl Peer {
	pub fn new(num_neighbours: usize) -> Self {
		let mut neighbours = Vec::with_capacity(num_neighbours);
		(0..num_neighbours).for_each(|_| neighbours.push(None));
		// Sanity check:
		assert!(neighbours.len() == num_neighbours);
		assert!(neighbours.capacity() == num_neighbours);
		Peer {
			neighbours,
			cached_neighbour_opinion: HashMap::new(),
			cached_local_opinion: HashMap::new(),
			global_scores: HashMap::new(),
		}
	}

	pub fn add_neighbour(&mut self, peer_id: PeerId) -> Result<(), EigenError> {
		let first_available = self.neighbours.iter().position(|n| n.is_none());
		if let Some(index) = first_available {
			self.neighbours[index] = Some(Neighbour::new(peer_id));
			return Ok(());
		}
		Err(EigenError::MaxNeighboursReached)
	}

	pub fn remove_neighbour(&mut self, peer_id: PeerId) -> Result<(), EigenError> {
		let index = self
			.neighbours
			.iter()
			.position(|n| n.as_ref().map(|n| n.peer_id == peer_id).unwrap_or(false));
		if let Some(index) = index {
			self.neighbours[index] = None;
			return Ok(());
		}
		Err(EigenError::NeighbourNotFound)
	}

	pub fn iter_neighbours(
		&self,
		mut f: impl FnMut(&Neighbour) -> Result<(), EigenError>,
	) -> Result<(), EigenError> {
		for neighbour in self.neighbours.iter().flatten() {
			f(neighbour)?;
		}

		Ok(())
	}

	pub fn calculate_local_opinions(&mut self, k: Epoch) -> Result<(), EigenError> {
		let mut global_score = 0.;
		let mut sum_of_scores = 0;

		self.iter_neighbours(|Neighbour { peer_id, score }| {
			let opinion = self.get_neighbour_opinion(&(*peer_id, k));
			global_score += opinion.get_product();
			sum_of_scores += score;
			Ok(())
		})?;

		let mut opinions = Vec::new();
		self.iter_neighbours(|neighbour| {
			let normalized_score = neighbour.get_normalized_score(sum_of_scores);
			let product = global_score * normalized_score;
			let opinion = Opinion::new(k.next(), normalized_score, global_score, product);

			opinions.push((neighbour.get_peer_id(), opinion));
			Ok(())
		})?;

		for (peer_id, opinion) in opinions {
			self.cache_local_opinion((peer_id, opinion.get_epoch()), opinion);
		}
		self.global_scores.insert(k.next(), global_score);

		Ok(())
	}

	pub fn get_global_score(&self, k: Epoch) -> f64 {
		*self.global_scores.get(&k).unwrap_or(&0.)
	}

	pub fn get_local_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self.cached_local_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_local_opinion(&mut self, key: (PeerId, Epoch), response: Opinion) {
		self.cached_local_opinion.insert(key, response);
	}

	pub fn get_neighbour_opinion(&self, key: &(PeerId, Epoch)) -> Opinion {
		*self.cached_neighbour_opinion
			.get(key)
			.unwrap_or(&Opinion::empty(key.1))
	}

	pub fn cache_neighbour_opinion(&mut self, key: (PeerId, Epoch), response: Opinion) {
		self.cached_neighbour_opinion.insert(key, response);
	}
}
