use std::collections::{HashMap, HashSet};

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
		let (filtered_set, mut filtered_ops) = self.filter_peers();

		// Normalize the opinion scores
		// Distribute the credits(INITIAL_SCORE) to the valid opinion values
		// We assume that the initial credit of peer is constant(INITIAL_SCORE)
		for i in 0..NUM_NEIGHBOURS {
			let (pk, credits) = filtered_set[i];
			if !(pk == PublicKey::default() || credits == Fr::zero()) {
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

	fn filter_peers(
		&self,
	) -> (
		[(PublicKey, Fr); NUM_NEIGHBOURS],
		HashMap<PublicKey, Opinion>,
	) {
		let mut filtered_set: [(PublicKey, Fr); NUM_NEIGHBOURS] = self.set.clone();
		let mut filtered_ops: HashMap<PublicKey, Opinion> = HashMap::new();

		let mut valid_peers: Vec<PublicKey> = vec![];

		// Convert the peer who didn't sign his opinion, to default peer
		//
		// Example:
		//  In this set, peer3 didn't sign the opinion.
		//		[(p1, 10), (p2, 10), (p3, 0)]
		//   => [(p1, 10), (p2, 10), (null, 0)]
		// Here, "null" means default peer
		for i in 0..NUM_NEIGHBOURS {
			let (pk, credits) = filtered_set[i].clone();
			// If no credits, the peer did not sign his opinion
			if credits == Fr::zero() {
				filtered_set[i] = (PublicKey::default(), Fr::zero());
			} else {
				valid_peers.push(pk);
			}
		}

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = filtered_set[i].clone();
			if pk_i != PublicKey::default() {
				let mut ops_i = self.ops.get(&pk_i).unwrap().clone();

				// Give zero score for peers
				//   - giving scores to itself
				// 	 - giving scores to default peer
				//
				// Example:
				//   Peer1 opinion
				//		[(p1, 10), (p2, 10), (null, 10)]
				// 	 => [(p1,  0), (p2, 10), (null,  0)]
				//
				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, score) = ops_i.scores[j].clone();
					let true_pk = if i == j {
						pk_i
					} else if pk_j == pk_i {
						PublicKey::default()
					} else {
						pk_j
					};
					let true_score = if true_pk == pk_i || true_pk == PublicKey::default() {
						Fr::zero()
					} else {
						score
					};
					ops_i.scores[j] = (true_pk, true_score);
				}

				// Update the opinion array - pairs of (key, score)
				//
				// Example 1:
				// 	filtered_set => [p1, null, p3]
				//	Peer1 opinion
				// 		[(p1, 0), (p6, 10),  (p3, 10)]
				//   => [(p1, 0), (null, 0), (p3, 10)]
				//
				// Example 2:
				// 	filtered_set => [p1, p2, p3]
				//	Peer1 opinion
				// 		[(p1, 0), (p3, 10), (null, 0)]
				//   => [(p1, 0), (p2, 0),  (p3, 0)]
				let op_score_sum =
					ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
				if op_score_sum == Fr::zero() {
					panic!("The peer {i} didn't give any score to other peers!");
				}
				for j in 0..NUM_NEIGHBOURS {
					let (set_pk_j, _) = filtered_set[j];
					let (op_pk_j, _) = ops_i.scores[j].clone();

					if set_pk_j == PublicKey::default() {
						ops_i.scores[j] = (PublicKey::default(), Fr::zero());
					} else {
						if op_pk_j != set_pk_j {
							ops_i.scores[j] = (set_pk_j, Fr::zero());
						}
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
				// Example 2: (Cont.d from above example 2)
				// 	filtered_set => [p1, p2, p3]
				//	Peer1 opinion
				//      [(p1, 0), (p2, 0), (p3, 0)]
				//   => [(p1, 0), (p2, 1), (p3, 1)]
				let new_op_score_sum =
					ops_i.scores.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
				if new_op_score_sum == Fr::zero() {
					for j in 0..NUM_NEIGHBOURS {
						let (pk_j, _) = ops_i.scores[j].clone();
						if i != j && valid_peers.contains(&pk_j) {
							ops_i.scores[j] = (pk_j, Fr::from(1));
						}
					}
				}

				filtered_ops.insert(pk_i, ops_i);
			}
		}

		(filtered_set, filtered_ops)
	}
}

#[cfg(test)]
mod test {
	use super::{EigenTrustSet, Opinion, INITIAL_SCORE, NUM_NEIGHBOURS};
	use crate::{
		calculate_message_hash,
		eddsa::native::{sign, PublicKey, SecretKey, Signature},
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
