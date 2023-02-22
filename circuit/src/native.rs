use std::collections::HashMap;

use crate::eddsa::native::{PublicKey, Signature};
use halo2::{
	arithmetic::Field,
	halo2curves::{bn256::Fr, FieldExt},
};

const NUM_NEIGHBOURS: usize = 6;
const NUM_ITERATIONS: usize = 20;
const INITIAL_SCORE: u128 = 1000;

#[derive(Debug, Clone)]
struct Opinion {
	sig: Signature,
	message_hash: Fr,
	scores: [(PublicKey, Fr); NUM_NEIGHBOURS],
}

impl Opinion {
	pub fn new(
		sig: Signature, message_hash: Fr, scores: [(PublicKey, Fr); NUM_NEIGHBOURS],
	) -> Self {
		Self { sig, message_hash, scores }
	}
}

impl Default for Opinion {
	fn default() -> Self {
		let sig = Signature::new(Fr::zero(), Fr::zero(), Fr::zero());
		let message_hash = Fr::zero();
		let scores = [(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS];
		Self { sig, message_hash, scores }
	}
}

struct EigenTrustSet {
	set: [(PublicKey, Fr); NUM_NEIGHBOURS],
	ops: HashMap<PublicKey, Opinion>,
}

impl EigenTrustSet {
	pub fn new() -> Self {
		Self { set: [(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS], ops: HashMap::new() }
	}

	pub fn add_member(&mut self, pk: PublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x == PublicKey::default());
		let index = first_available.unwrap();

		// Initial score for new member is zero.
		self.set[index] = (pk, Fr::zero());
	}

	pub fn remove_member(&mut self, pk: PublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (PublicKey::default(), Fr::zero());

		self.ops.remove(&pk);
	}

	pub fn update_op(&mut self, from: PublicKey, op: Opinion) {
		let pos_from = self.set.iter().position(|&(x, _)| x == from);
		assert!(pos_from.is_some());

		// Initial score is updated only when the opinion is given/signed.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		let index = pos_from.unwrap();
		self.set[index] = (from, initial_score);

		self.ops.insert(from, op);
	}

	pub fn converge(&mut self) -> [Fr; NUM_NEIGHBOURS] {
		let mut filtered_set = self.set.clone();
		let mut filtered_ops: HashMap<PublicKey, Opinion> = HashMap::new();

		// Validity checks

		// Nullify opinion scores that are given to wrong member at specific index
		for i in 0..NUM_NEIGHBOURS {
			let (pk, credits) = filtered_set[i];

			if pk == PublicKey::default() || credits == Fr::zero() {
				assert!(self.ops.get(&pk).is_none());
			} else {
				let mut ops_i = self.ops.get(&pk).unwrap().clone();

				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, score) = ops_i.scores[j].clone();
					let true_score =
						if j != i && self.set[j].0 == pk_j { score } else { Fr::zero() };
					ops_i.scores[j].1 = true_score;
				}

				filtered_ops.insert(pk, ops_i);
			}
		}

		//  Filter the set -- set after we invalidated invalid peers:
		// 		- Peers that dont have at least one valid score
		for i in 0..NUM_NEIGHBOURS {
			let (pk, credits) = filtered_set[i];

			if !(pk == PublicKey::default() || credits == Fr::zero()) {
				let ops_i = filtered_ops.get(&pk).unwrap();

				let op_score_sum =
					ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);

				if op_score_sum == Fr::zero() {
					filtered_set[i] = (PublicKey::default(), Fr::zero());
					filtered_ops.remove(&pk);
				}
			}
		}

		// Normalize the opinion scores
		// Distribute the credits(INITIAL_SCORE) to the valid opinion values
		// We assume that the initial credit of peer is constant(INITIAL_SCORE)
		for i in 0..NUM_NEIGHBOURS {
			let (pk, credits) = filtered_set[i];

			if !(pk == PublicKey::default()) {
				let mut ops_i = filtered_ops.get_mut(&pk).unwrap();

				let op_score_sum =
					ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);

				for j in 0..NUM_NEIGHBOURS {
					let (_, op_score) = ops_i.scores[j].clone();
					ops_i.scores[j].1 = op_score * op_score_sum.invert().unwrap() * credits;
				}
			}
		}

		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = filtered_set.iter().filter(|(_, credits)| credits != &Fr::zero()).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		// By this point we should use filtered_set and filtered_opinions
		let mut s = filtered_set.map(|item| item.1);
		let default_op = Opinion::default();
		for _ in 0..NUM_ITERATIONS {
			let mut distributions = [[Fr::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
			for i in 0..NUM_NEIGHBOURS {
				let mut local_distr = [Fr::zero(); NUM_NEIGHBOURS];
				let pk = filtered_set[i].0;
				let ops_i = filtered_ops.get(&pk).unwrap_or_else(|| &default_op);

				for j in 0..NUM_NEIGHBOURS {
					let op = ops_i.scores[j].1 * s[i];
					local_distr[j] = op;
				}
				distributions[i] = local_distr;
			}

			let mut new_s = [Fr::zero(); NUM_NEIGHBOURS];
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					new_s[i] += distributions[j][i];
				}
			}

			s = new_s;
		}

		println!("new s: {:?}", s);

		let mut sum = Fr::zero();
		for x in s.iter() {
			sum += x;
		}
		println!("sum: {:?}", sum);

		s
	}
}

#[cfg(test)]
mod test {
	use super::{EigenTrustSet, Opinion, INITIAL_SCORE, NUM_NEIGHBOURS};
	use crate::{
		calculate_message_hash,
		eddsa::native::{sign, PublicKey, SecretKey},
	};
	use halo2::halo2curves::{bn256::Fr, FieldExt};
	use rand::thread_rng;

	#[test]
	#[should_panic]
	fn test_add_member_in_initial_set() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let pk1 = sk1.public();

		set.add_member(pk1);

		// Re-adding the member should panic
		set.add_member(pk1);
	}

	#[test]
	#[should_panic]
	fn test_add_two_members_without_opinions() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();

		set.add_member(pk1);
		set.add_member(pk2);

		set.converge();
	}

	#[test]
	#[should_panic]
	fn test_add_two_members_with_one_opinion() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let pks = [
			pk1,
			pk2,
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
		];
		let scores = [
			Fr::zero(),
			Fr::from_u128(INITIAL_SCORE),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
		];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_opinions() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let pks = [
			pk1,
			pk2,
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
		];
		let scores = [
			Fr::zero(),
			Fr::from_u128(INITIAL_SCORE),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
		];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		// Peer2(pk2) signs the opinion
		let pks = [
			pk1,
			pk2,
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
			PublicKey::default(),
		];
		let scores = [
			Fr::from_u128(INITIAL_SCORE),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
			Fr::zero(),
		];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk2, &pk2, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk2, op);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_opinions() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::zero(), Fr::from(300), Fr::from(700), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk2, &pk2, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk2, op);

		// Peer3(pk3) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk3, &pk3, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk3, op);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_two_opinions() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::zero(), Fr::from(300), Fr::from(700), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk2, &pk2, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk2, op);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_3_ops_quit_1_member() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::zero(), Fr::from(300), Fr::from(700), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk2, &pk2, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk2, op);

		// Peer3(pk3) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk3, &pk3, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk3, op);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2);

		set.converge();
	}

	#[test]
	#[should_panic]
	fn test_add_3_members_with_2_ops_quit_1_member_1_op() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::zero(), Fr::from(300), Fr::from(700), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk1, &pk1, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk1, op);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(&sk2, &pk2, message_hashes[0]);

		let scores = pks.zip(scores);
		let op = Opinion::new(sig, message_hashes[0], scores);

		set.update_op(pk2, op);

		set.converge();

		// Peer1 quits
		set.remove_member(pk1);

		set.converge();
	}
}
