use libp2p::PeerId;
use crate::EigenError;

#[derive(Clone, Copy, Debug)]
pub struct Neighbour {
	peer_id: PeerId,
	score: u32,
}

impl Neighbour {
	pub fn new(peer_id: PeerId) -> Self {
		Self { peer_id, score: 0 }
	}
}

pub struct Peer<const N: usize> {
	neighbours: [Option<Neighbour>; N],
	score: u32,
}

impl<const N: usize> Peer<N> {
	pub fn new() -> Self {
		Peer {
			neighbours: [None; N],
			score: 0,
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
}