use std::collections::HashMap;

use crate::eddsa::native::{PublicKey, Signature};
use halo2::{
	arithmetic::Field,
	halo2curves::{bn256::Fr, ff::PrimeField},
};
use itertools::Itertools;

/// Opinion info of peer
#[derive(Debug, Clone)]
pub struct Opinion<const NUM_NEIGHBOURS: usize> {
	/// Signature of opinion
	pub sig: Signature,
	/// Hash of opinion message
	pub message_hash: Fr,
	/// Array of real opinions
	pub scores: Vec<(PublicKey, Fr)>,
}

impl<const NUM_NEIGHBOURS: usize> Opinion<NUM_NEIGHBOURS> {
	/// Constructs the instance of `Opinion`
	pub fn new(sig: Signature, message_hash: Fr, scores: Vec<(PublicKey, Fr)>) -> Self {
		Self { sig, message_hash, scores }
	}
}

impl<const NUM_NEIGHBOURS: usize> Default for Opinion<NUM_NEIGHBOURS> {
	fn default() -> Self {
		let sig = Signature::new(Fr::zero(), Fr::zero(), Fr::zero());
		let message_hash = Fr::zero();
		let scores = vec![(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS];
		Self { sig, message_hash, scores }
	}
}

/// Dynamic set for EigenTrust
pub struct EigenTrustSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
	const SCALE: u128,
> {
	set: Vec<(PublicKey, Fr)>,
	ops: HashMap<PublicKey, Opinion<NUM_NEIGHBOURS>>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	> EigenTrustSet<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>
{
	/// Constructs new instance
	pub fn new() -> Self {
		Self {
			set: vec![(PublicKey::default(), Fr::zero()); NUM_NEIGHBOURS],
			ops: HashMap::new(),
		}
	}

	/// Add new set member and initial score
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

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: PublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (PublicKey::default(), Fr::zero());

		self.ops.remove(&pk);
	}

	/// Update the opinion of the member
	pub fn update_op(&mut self, from: PublicKey, op: Opinion<NUM_NEIGHBOURS>) {
		let pos_from = self.set.iter().position(|&(x, _)| x == from);
		assert!(pos_from.is_some());

		self.ops.insert(from, op);
	}

	/// Get a specific opinion from a peer
	pub fn get_op(&self, from: &PublicKey) -> Opinion<NUM_NEIGHBOURS> {
		self.ops.get(from).cloned().unwrap_or(Opinion::default())
	}

	/// Compute the EigenTrust score
	pub fn converge(&self) -> (Vec<Fr>, Vec<Fr>) {
		let mut filtered_ops: HashMap<PublicKey, Opinion<NUM_NEIGHBOURS>> = self.filter_peers_ops();

		// Normalize the opinion scores
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == PublicKey::default() {
				continue;
			}
			let ops_i = filtered_ops.get_mut(&pk).unwrap();

			let op_score_sum = ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
			let inverted_sum = op_score_sum.invert().unwrap_or(Fr::zero());

			for j in 0..NUM_NEIGHBOURS {
				let (_, op_score) = ops_i.scores[j].clone();
				ops_i.scores[j].1 = op_score * inverted_sum;
			}
		}

		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = self.set.iter().filter(|(pk, _)| pk != &PublicKey::default()).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		// By this point we should use filtered_opinions
		let mut s: Vec<Fr> = self.set.iter().map(|(_, score)| score.clone()).collect();
		for _ in 0..NUM_ITERATIONS {
			let mut sop = Vec::new();
			for i in 0..NUM_NEIGHBOURS {
				let pk_i = self.set[i].0.clone();
				let n_score = s[i];
				if pk_i == PublicKey::default() {
					sop.push(vec![Fr::zero(); NUM_NEIGHBOURS]);
					continue;
				}

				let op_i = filtered_ops.get(&pk_i).unwrap();

				let mut sop_i = Vec::new();
				for j in 0..NUM_NEIGHBOURS {
					let score = op_i.scores[j].1;
					let res = score * n_score;
					sop_i.push(res);
				}
				sop.push(sop_i);
			}

			for i in 0..NUM_NEIGHBOURS {
				let mut new_score = Fr::zero();
				for j in 0..NUM_NEIGHBOURS {
					new_score += sop[j][i];
				}
				s[i] = new_score;
			}
		}

		// Apply scaling for converting large final scores to small values (easy to read)
		let scale_factor = Fr::from_u128(SCALE);
		let scaled: Vec<Fr> = s.iter().map(|p| p * scale_factor).collect_vec();

		// Assert the score sum for checking the possible reputation leak
		let sum_initial = self.set.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
		let sum_final = s.iter().fold(Fr::zero(), |acc, &score| acc + score);
		assert!(sum_initial == sum_final);

		(s, scaled)
	}

	fn filter_peers_ops(&self) -> HashMap<PublicKey, Opinion<NUM_NEIGHBOURS>> {
		let mut filtered_ops: HashMap<PublicKey, Opinion<NUM_NEIGHBOURS>> = HashMap::new();

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = self.set[i].clone();
			if pk_i == PublicKey::default() {
				continue;
			}

			let mut ops_i = self.ops.get(&pk_i).unwrap_or(&Opinion::default()).clone();

			// Update the opinion array - pairs of (key, score)
			//
			// Example 1:
			// 	set => [p1, null, p3]
			//	Peer1 opinion
			// 		[(p1, 10), (p6, 10),  (p3, 10)]
			//   => [(p1, 0), (null, 0), (p3, 10)]
			//
			// Example 2:
			// 	set => [p1, p2, null]
			//	Peer1 opinion
			// 		[(p1, 0), (p3, 10), (null, 10)]
			//   => [(p1, 0), (p2, 0),  (p3, 0)]
			for j in 0..NUM_NEIGHBOURS {
				let (set_pk_j, _) = self.set[j];
				let (op_pk_j, _) = ops_i.scores[j].clone();

				let is_diff_pk_j = set_pk_j != op_pk_j;
				let is_pk_j_null = set_pk_j == PublicKey::default();
				let is_pk_i = set_pk_j == pk_i;

				// Conditions for nullifying the score
				// 1. set_pk_j != op_pk_j
				// 2. set_pk_j == 0 (null or default key)
				// 3. set_pk_j == pk_i
				if is_diff_pk_j || is_pk_j_null || is_pk_i {
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
			// 	set => [p1, p2, p3]
			//	Peer1 opinion
			// 		[(p1, 0), (p2, 0), (p3, 10)]
			//   => [(p1, 0), (p2, 0), (p3, 10)]
			//
			// Example 2:
			// 	set => [p1, p2, p3]
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

		filtered_ops
	}
}

#[cfg(test)]
mod test {
	use std::time::Instant;

	use super::{EigenTrustSet, Opinion};
	use crate::{
		calculate_message_hash,
		eddsa::native::{sign, PublicKey, SecretKey},
		integer::native::Integer,
		rns::decompose_big,
		utils::fe_to_big,
	};

	use halo2::halo2curves::{bn256::Fr, ff::PrimeField};
	use itertools::Itertools;
	use rand::{thread_rng, Rng};

	const NUM_NEIGHBOURS: usize = 12;
	const NUM_ITERATIONS: usize = 10;
	const INITIAL_SCORE: u128 = 1000;
	const SCALE: u128 = 100000;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		sk: &SecretKey, pk: &PublicKey, pks: &[PublicKey], scores: &[Fr],
	) -> Opinion<NUM_NEIGHBOURS> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);

		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(sk, pk, message_hashes[0]);

		// let scores = pks.zip(*scores);
		let mut op_scores = vec![];
		for i in 0..NUM_NEIGHBOURS {
			op_scores.push((pks[i], scores[i]));
		}
		let op = Opinion::new(sig, message_hashes[0], op_scores.to_vec());
		op
	}

	#[test]
	#[should_panic]
	fn test_add_member_in_initial_set() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let pk1 = sk1.public();

		set.add_member(pk1);

		set.converge();
	}

	#[test]
	fn test_add_two_members_without_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		set.update_op(pk2, op2);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk3, &pk3, &pks, &scores,
		);

		set.update_op(pk3, op3);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_two_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		set.update_op(pk2, op2);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_3_ops_quit_1_member() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk3, &pk3, &pks, &scores,
		);

		set.update_op(pk3, op3);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_2_ops_quit_1_member_1_op() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

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
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		set.update_op(pk2, op2);

		set.converge();

		// // Peer1 quits
		// set.remove_member(pk1);

		// set.converge();
	}

	#[test]
	fn test_filter_peers_ops() {
		//	Filter the peers with following opinions:
		//			1	2	3	4	 5
		//		-----------------------
		//		1	10	10	.	.	10
		//		2	.	.	30	.	.
		//		3	10	.	.	.	.
		//		4	.	.	.	.	.
		//		5	.	.	.	.	.

		let rng = &mut thread_rng();

		let sk1 = SecretKey::random(rng);
		let sk2 = SecretKey::random(rng);
		let sk3 = SecretKey::random(rng);

		let pk1 = sk1.public();
		let pk2 = sk2.public();
		let pk3 = sk3.public();

		// Peer1(pk1) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);
		scores[1] = Fr::from_u128(10);

		let op1 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk1, &pk1, &pks, &scores,
		);

		// Peer2(pk2) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[2] = Fr::from_u128(30);

		let op2 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk2, &pk2, &pks, &scores,
		);

		// Peer3(pk3) signs the opinion
		let mut pks = [PublicKey::default(); NUM_NEIGHBOURS];
		pks[0] = pk1;
		pks[1] = pk2;
		pks[2] = pk3;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);

		let op3 = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
			&sk3, &pk3, &pks, &scores,
		);

		// Setup EigenTrustSet
		let mut eigen_trust_set =
			EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		eigen_trust_set.add_member(pk1);
		eigen_trust_set.add_member(pk2);
		eigen_trust_set.add_member(pk3);

		eigen_trust_set.update_op(pk1, op1);
		eigen_trust_set.update_op(pk2, op2);
		eigen_trust_set.update_op(pk3, op3);

		let filtered_ops = eigen_trust_set.filter_peers_ops();

		let final_peers_cnt =
			eigen_trust_set.set.iter().filter(|&&(pk, _)| pk != PublicKey::default()).count();
		let final_ops_cnt = filtered_ops.keys().count();
		assert!(final_peers_cnt == final_ops_cnt);
	}

	fn native_float<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	>(
		ops: Vec<Vec<f32>>,
	) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}
		let mut s: Vec<f32> = vec![INITIAL_SCORE as f32; NUM_NEIGHBOURS];

		let mut new_s = s.clone();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = 0.;
				for j in 0..NUM_NEIGHBOURS {
					let score = ops[j][i] * s[j];
					score_i_sum += score;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}

		let s_f: String = s.iter().map(|v| format!("{:>9.4}", v)).join(", ");
		println!("NATIVE FLOAT RESULT: [{}]", s_f);
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	>(
		ops: Vec<Vec<Fr>>,
	) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		let rng = &mut thread_rng();

		let sks: Vec<SecretKey> =
			(0..NUM_NEIGHBOURS).into_iter().map(|__| SecretKey::random(rng)).collect();
		let pks: Vec<PublicKey> = sks.clone().iter().map(|s| s.public()).collect();

		// Add the publicKey to the set
		pks.iter().for_each(|pk| set.add_member(*pk));

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();

			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&sks[i], &pks[i], &pks, &scores,
			);

			set.update_op(pks[i], op_i);
		}

		let (s, scaled) = set.converge();
		let s_formatted: Vec<String> = s.iter().map(|&x| fe_to_big(x).to_str_radix(10)).collect();
		println!("new s: {:#?}", s_formatted);
		let scaled_formatted: Vec<String> =
			scaled.iter().map(|&x| fe_to_big(x).to_str_radix(10)).collect();
		println!("scaled new s: {:#?}", scaled_formatted);
	}

	#[test]
	fn test_scaling_1() {
		const NUM_NEIGHBOURS: usize = 10;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 100000000000000000000000000000000000000;
		const SCALE: u128 = 100000000000000000000000000000000000000;

		let ops = [
			// 0 + 15 + 154 + 165 + 0 + 123 + 56 + 222 + 253 + 12 = 1000
			[0, 15, 154, 165, 0, 123, 56, 222, 253, 12], // - Peer 0 opinions
			// 210 + 0 + 10 + 210 + 20 + 10 + 20 + 30 + 440 + 50 = 1000
			[210, 0, 10, 210, 20, 10, 20, 30, 440, 50], // - Peer 1 opinions
			// 40 + 10 + 0 + 20 + 30 + 410 + 20 + 445 + 23 + 2 = 1000
			[40, 10, 0, 20, 30, 410, 20, 445, 23, 2], // - Peer 2 opinions
			// 10 + 18 + 20 + 0 + 310 + 134 + 45 + 12 + 439 + 12 = 1000
			[10, 18, 20, 0, 310, 134, 45, 12, 439, 12], // - Peer 3 opinions
			// 30 + 130 + 44 + 210 + 0 + 12 + 445 + 62 + 12 + 55 = 1000
			[30, 130, 44, 210, 0, 12, 445, 62, 12, 55], // = Peer 4 opinions
			[0, 15, 154, 165, 123, 0, 56, 222, 253, 12], // - Peer 5 opinions
			[210, 20, 10, 210, 20, 10, 0, 30, 440, 50], // - Peer 6 opinions
			[40, 10, 445, 20, 30, 410, 20, 0, 23, 2],   // - Peer 7 opinions
			[10, 18, 20, 439, 310, 134, 45, 12, 0, 12], // - Peer 8 opinions
			[30, 130, 44, 210, 55, 12, 445, 62, 12, 0], // = Peer 9 opinions
		]
		.map(|arr| arr.map(|x| Fr::from_u128(x)).to_vec())
		.to_vec();

		let ops_native = [
			[0.000, 0.015, 0.154, 0.165, 0.000, 0.123, 0.056, 0.222, 0.253, 0.012], // - Peer 0 opinions
			[0.210, 0.000, 0.010, 0.210, 0.020, 0.010, 0.020, 0.030, 0.440, 0.050], // - Peer 1 opinions
			[0.040, 0.010, 0.000, 0.020, 0.030, 0.410, 0.020, 0.445, 0.023, 0.002], // - Peer 2 opinions
			[0.010, 0.018, 0.020, 0.000, 0.310, 0.134, 0.045, 0.012, 0.439, 0.012], // - Peer 3 opinions
			[0.030, 0.130, 0.044, 0.210, 0.000, 0.012, 0.445, 0.062, 0.012, 0.055], // = Peer 4 opinions
			[0.000, 0.015, 0.154, 0.165, 0.123, 0.000, 0.056, 0.222, 0.253, 0.012], // - Peer 5 opinions
			[0.210, 0.020, 0.010, 0.210, 0.020, 0.010, 0.000, 0.030, 0.440, 0.050], // - Peer 6 opinions
			[0.040, 0.010, 0.445, 0.020, 0.030, 0.410, 0.020, 0.000, 0.023, 0.002], // - Peer 7 opinions
			[0.010, 0.018, 0.020, 0.439, 0.310, 0.134, 0.045, 0.012, 0.000, 0.012], // - Peer 8 opinions
			[0.030, 0.130, 0.044, 0.210, 0.055, 0.012, 0.445, 0.062, 0.012, 0.000], // = Peer 9 opinions
		]
		.map(|x| x.to_vec())
		.to_vec();

		let start = Instant::now();
		eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>(ops);
		native_float::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>(ops_native);
		let end = start.elapsed();
		println!("Convergence time: {:?}", end);
	}
}
