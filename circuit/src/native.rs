use crate::eddsa::native::PublicKey;
use halo2::halo2curves::bn256::Fr;

const NUM_NEIGHBOURS: usize = 6;

struct EigenTrustSet {
	set: [(PublicKey, Fr); NUM_NEIGHBOURS],
	ops: [[(PublicKey, Fr); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
}

impl EigenTrustSet {
	pub fn new() -> Self {
		Self {
			set: [(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS],
			ops: [[(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
		}
	}

	pub fn add_member(&mut self, pk: PublicKey, initial_score: Fr) {
		let pos = self.set.iter().position(|&(x, _)| x == PublicKey::default());
		let first_available = self.set.iter().position(|&(x, _)| x == PublicKey::default());
		// Make sure not already in the set
		assert!(pos.is_none());

		let index = first_available.unwrap();
		self.set[index] = (pk, initial_score);
	}

	pub fn update_op(&mut self, from: PublicKey, to: PublicKey, score: Fr) {
		let pos_from = self.set.iter().position(|&(x, _)| x == from);
		let pos_to = self.set.iter().position(|&(x, _)| x == to);

		let index_from = pos_from.unwrap();
		let index_to = pos_to.unwrap();

		self.ops[index_from][index_to] = (to, score);
	}

	pub fn converge(&self) -> [Fr; NUM_NEIGHBOURS] {
		[Fr::zero(); NUM_NEIGHBOURS]
	}
}
