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
	ops_validity: HashMap<PublicKey, Option<bool>>,
}

impl EigenTrustSet {
	pub fn new() -> Self {
		Self {
			set: [(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS],
			ops: HashMap::new(),
			ops_validity: HashMap::new(),
		}
	}

	pub fn add_member(&mut self, pk: PublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x == PublicKey::default());
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		self.set[index] = (pk, initial_score);
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

		self.ops.insert(from, op);
	}

	pub fn converge(&self) -> [(PublicKey, Fr); NUM_NEIGHBOURS] {
		let (filtered_set, mut filtered_ops) = self.filter_peers();

		// Normalize the opinion scores
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = filtered_set[i];
			if pk == PublicKey::default() {
				continue;
			}
			let mut ops_i = filtered_ops.get_mut(&pk).unwrap();

			let op_score_sum = ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
			let inverted_sum = op_score_sum.invert().unwrap_or(Fr::zero());

			for j in 0..NUM_NEIGHBOURS {
				let (_, op_score) = ops_i.scores[j].clone();
				ops_i.scores[j].1 = op_score * inverted_sum;
			}
		}

		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = filtered_set.iter().filter(|(pk, _)| pk != &PublicKey::default()).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		// By this point we should use filtered_set and filtered_opinions
		let mut s = filtered_set.clone();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let (pk_i, _) = s[i];
				if pk_i == PublicKey::default() {
					continue;
				}

				let mut new_score = Fr::zero();
				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, n_score) = s[j];
					if pk_j == PublicKey::default() {
						continue;
					}

					let ops_j = filtered_ops.get(&pk_j).unwrap();
					let score = ops_j.scores[i].1;
					let op = score * n_score;
					new_score += op;
				}
				s[i].1 = new_score;
			}
		}

		println!("new s: {:#?}", s.map(|p| p.1));

		let sum_initial = filtered_set.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
		let sum_final = s.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
		// TODO: Make sure that the total amount of reputation stays the same after
		// convergence
		// assert!(sum_initial == sum_final);
		println!("sum before: {:?}, sum after: {:?}", sum_initial, sum_final);

		s
	}

	fn filter_peers(
		&self,
	) -> (
		[(PublicKey, Fr); NUM_NEIGHBOURS],
		HashMap<PublicKey, Opinion>,
	) {
		let filtered_set: [(PublicKey, Fr); NUM_NEIGHBOURS] = self.set.clone();
		let mut filtered_ops: HashMap<PublicKey, Opinion> = HashMap::new();

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = filtered_set[i].clone();
			if pk_i == PublicKey::default() {
				continue;
			}

			let mut ops_i = self.ops.get(&pk_i).unwrap_or(&Opinion::default()).clone();

			// Update the opinion array - pairs of (key, score)
			//
			// Example 1:
			// 	filtered_set => [p1, null, p3]
			//	Peer1 opinion
			// 		[(p1, 10), (p6, 10),  (p3, 10)]
			//   => [(p1, 0), (null, 0), (p3, 10)]
			//
			// Example 2:
			// 	filtered_set => [p1, p2, null]
			//	Peer1 opinion
			// 		[(p1, 0), (p3, 10), (null, 10)]
			//   => [(p1, 0), (p2, 0),  (p3, 0)]
			for j in 0..NUM_NEIGHBOURS {
				let (set_pk_j, _) = filtered_set[j];
				let (op_pk_j, _) = ops_i.scores[j].clone();

				let is_diff_pk_j = set_pk_j != op_pk_j;
				let is_pk_j_zero = set_pk_j == PublicKey::default();
				let is_pk_i = set_pk_j == pk_i;

				// Conditions for nullifying the score
				// 1. set_pk_j != op_pk_j
				// 2. set_pk_j == 0
				// 3. set_pk_j == pk_i
				if is_diff_pk_j || is_pk_j_zero || is_pk_i {
					ops_i.scores[j].1 = Fr::zero();
				}

				// Condition for correcting the pk
				// 1. set_pk_j != op_pk_j
				if is_diff_pk_j {
					ops_i.scores[j].0 = set_pk_j;
				}
			}

			// Distribute the scores
			//
			// Example 1:
			// 	filtered_set => [p1, p2, p3]
			//	Peer1 opinion
			// 		[(p1, 0), (p2, 0), (p3, 10)]
			//   => [(p1, 0), (p2, 0), (p3, 10)]
			//
			// Example 2:
			// 	filtered_set => [p1, p2, p3]
			//	Peer1 opinion
			//      [(p1, 0), (p2, 0), (p3, 0)]
			//   => [(p1, 0), (p2, 1), (p3, 1)]
			let op_score_sum = ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
			if op_score_sum == Fr::zero() {
				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, _) = ops_i.scores[j].clone();

					let is_diff_pk = pk_j != pk_i;
					let is_not_null = pk_j != PublicKey::default();

					// Conditions for distributing the score
					// 1. pk_j != pk_i
					// 2. pk_j != PublicKey::default()
					if is_diff_pk && is_not_null {
						ops_i.scores[j] = (pk_j, Fr::from(1));
					}
				}
			}

			filtered_ops.insert(pk_i, ops_i);
		}

		(filtered_set, filtered_ops)
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

	fn sign_opinion(
		sk: &SecretKey, pk: &PublicKey, pks: &[PublicKey; NUM_NEIGHBOURS],
		scores: &[Fr; NUM_NEIGHBOURS],
	) -> Opinion {
		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(sk, pk, message_hashes[0]);

		let scores = pks.zip(*scores);
		let op = Opinion::new(sig, message_hashes[0], scores);
		op
	}

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
	fn test_one_member_converge() {
		let mut set = EigenTrustSet::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let pk1 = sk1.public();

		set.add_member(pk1);

		set.converge();
	}

	#[test]
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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

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
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		set.update_op(pk2, op2);

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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
		let op3 = sign_opinion(&sk3, &pk3, &pks, &scores);

		set.update_op(pk3, op3);

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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		set.update_op(pk2, op2);

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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
		let op3 = sign_opinion(&sk3, &pk3, &pks, &scores);

		set.update_op(pk3, op3);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2);

		set.converge();
	}

	#[test]
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
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(600), Fr::zero(), Fr::from(400), Fr::zero(), Fr::zero(), Fr::zero()];
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		set.update_op(pk2, op2);

		set.converge();

		// Peer1 quits
		set.remove_member(pk1);

		set.converge();
	}

	#[test]
	fn test_filter_peers() {
		//	Filter the peers with following opinions:
		//			1	2	3	4	5	6
		//		--------------------------
		//		1	10	10	.	.	10	.
		//		2	.	.	30	.	.	.
		//		3	10	.	.	.	.	.
		//		4	.	.	.	.	.	.
		//		5	.	.	.	.	.	.
		//		6	.	.	.	.	.	.
		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);
		let sk8 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();
		let pk8 = sk8.public();

		// Peer1(pk1) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), pk8];
		let scores = [Fr::from(10), Fr::from(10), Fr::zero(), Fr::zero(), Fr::from(10), Fr::zero()];
		let op1 = sign_opinion(&sk1, &pk1, &pks, &scores);

		// Peer2(pk2) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::zero(), Fr::zero(), Fr::from(30), Fr::zero(), Fr::zero(), Fr::zero()];
		let op2 = sign_opinion(&sk2, &pk2, &pks, &scores);

		// Peer3(pk3) signs the opinion
		let pks = [pk1, pk2, pk3, PublicKey::default(), PublicKey::default(), PublicKey::default()];
		let scores = [Fr::from(10), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
		let op3 = sign_opinion(&sk3, &pk3, &pks, &scores);

		// Setup EigenTrustSet
		let mut set = EigenTrustSet::new();

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		set.update_op(pk1, op1);
		set.update_op(pk2, op2);
		set.update_op(pk3, op3);

		let (filtered_set, filtered_ops) = set.filter_peers();

		let final_peers_cnt =
			filtered_set.iter().filter(|&&(pk, _)| pk != PublicKey::default()).count();
		let final_ops_cnt = filtered_ops.keys().count();
		assert!(final_peers_cnt == final_ops_cnt);
	}
}
