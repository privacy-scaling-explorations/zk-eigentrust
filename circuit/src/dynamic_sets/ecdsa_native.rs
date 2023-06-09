use crate::{
	circuit::PoseidonNativeHasher,
	opinion::native::Opinion,
	rns::{compose_big_decimal_f, decompose_big_decimal},
	utils::fe_to_big,
};
use halo2::{
	arithmetic::Field,
	halo2curves::{bn256::Fr, ff::PrimeField},
};
use itertools::Itertools;
use num_bigint::{BigInt, ToBigInt};
use num_rational::BigRational;
use num_traits::{FromPrimitive, Zero};
use secp256k1::{constants::ONE, ecdsa, Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

/// ECDSA public key
pub type ECDSAPublicKey = secp256k1::PublicKey;
/// ECDSA signature
pub type ECDSASignature = ecdsa::RecoverableSignature;

/// Construct an Ethereum address for the given ECDSA public key
pub fn address_from_pub_key(pub_key: &ECDSAPublicKey) -> Result<[u8; 20], &'static str> {
	let pub_key_bytes: [u8; 65] = pub_key.serialize_uncompressed();

	// Hash with Keccak256
	let mut hasher = Keccak256::new();
	hasher.update(&pub_key_bytes[1..]);
	let hashed_public_key = hasher.finalize().to_vec();

	// Get the last 20 bytes of the hash
	let mut address = [0u8; 20];
	address.copy_from_slice(&hashed_public_key[hashed_public_key.len() - 20..]);

	Ok(address)
}

/// Calculate the address field value from a public key
pub fn field_value_from_pub_key(&pub_key: &ECDSAPublicKey) -> Fr {
	let mut address = address_from_pub_key(&pub_key).unwrap();
	address.reverse();

	let mut address_bytes = [0u8; 32];
	address_bytes[..address.len()].copy_from_slice(&address);

	Fr::from_bytes(&address_bytes).unwrap()
}

/// Attestation submission struct
#[derive(Clone, Debug)]
pub struct SignedAttestation {
	/// Attestation
	pub attestation: AttestationFr,
	/// Signature
	pub signature: ECDSASignature,
}

impl SignedAttestation {
	/// Constructs a new instance
	pub fn new(attestation: AttestationFr, signature: ECDSASignature) -> Self {
		Self { attestation, signature }
	}

	/// Recover the public key from the attestation signature
	pub fn recover_public_key(&self) -> Result<ECDSAPublicKey, &'static str> {
		let message = self.attestation.hash().to_bytes();

		let public_key = self
			.signature
			.recover(&Message::from_slice(message.as_slice()).unwrap())
			.map_err(|_| "Failed to recover public key")?;

		Ok(public_key)
	}
}

impl Default for SignedAttestation {
	fn default() -> Self {
		let attestation = AttestationFr::default();

		let s = Secp256k1::signing_only();
		let msg = attestation.hash().to_bytes();
		let sk = SecretKey::from_slice(&ONE).unwrap();
		let signature =
			s.sign_ecdsa_recoverable(&Message::from_slice(msg.as_slice()).unwrap(), &sk);

		Self { attestation, signature }
	}
}

/// Attestation struct
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AttestationFr {
	/// Ethereum address of peer being rated
	pub about: Fr,
	/// Unique identifier for the action being rated
	pub domain: Fr,
	/// Given rating for the action
	pub value: Fr,
	/// Optional field for attaching additional information to the attestation
	pub message: Fr,
}

impl AttestationFr {
	/// Construct a new attestation struct
	pub fn new(about: Fr, domain: Fr, value: Fr, message: Fr) -> Self {
		Self { about, domain, value, message }
	}

	/// Hash attestation
	pub fn hash(&self) -> Fr {
		PoseidonNativeHasher::new([self.about, self.domain, self.value, self.message, Fr::zero()])
			.permute()[0]
	}
}

impl Default for AttestationFr {
	fn default() -> Self {
		AttestationFr {
			about: Fr::default(),
			domain: Fr::default(),
			value: Fr::default(),
			message: Fr::default(),
		}
	}
}

/// Witness structure for proving threshold checks
pub struct ThresholdWitness<const NUM_LIMBS: usize> {
	threshold: Fr,
	is_bigger: bool,
	num_decomposed: [Fr; NUM_LIMBS],
	den_decomposed: [Fr; NUM_LIMBS],
}

/// Dynamic set for EigenTrust
pub struct EigenTrustSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
> {
	set: Vec<(Fr, Fr)>,
	ops: HashMap<Fr, Vec<Fr>>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITERATIONS: usize, const INITIAL_SCORE: u128>
	EigenTrustSet<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>
{
	/// Constructs new instance
	pub fn new() -> Self {
		Self { set: vec![(Fr::zero(), Fr::zero()); NUM_NEIGHBOURS], ops: HashMap::new() }
	}

	/// Add new set member and initial score
	pub fn add_member(&mut self, pk: Fr) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x == Fr::zero());
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		self.set[index] = (pk, initial_score);
	}

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: Fr) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (Fr::zero(), Fr::zero());

		self.ops.remove(&pk);
	}

	/// Update the opinion of the member
	pub fn update_op(&mut self, from: ECDSAPublicKey, op: Vec<Option<SignedAttestation>>) -> Fr {
		let default_att = SignedAttestation::default();
		let op_unwrapped =
			op.iter().map(|x| x.clone().unwrap_or(default_att.clone())).collect_vec();
		let op = Opinion::<NUM_NEIGHBOURS>::new(from, op_unwrapped);
		let set = self.set.iter().map(|&(pk, _)| pk.clone()).collect();
		let (from_pk, scores, op_hash) = op.validate(set);

		self.ops.insert(from_pk, scores);

		return op_hash;
	}

	/// Method for filtering invalid opinions
	fn filter_peers_ops(&self) -> HashMap<Fr, Vec<Fr>> {
		let mut filtered_ops: HashMap<Fr, Vec<Fr>> = HashMap::new();

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = self.set[i].clone();
			if pk_i == Fr::zero() {
				continue;
			}

			let default_ops = vec![Fr::default(); NUM_NEIGHBOURS];
			let mut ops_i = self.ops.get(&pk_i).unwrap_or(&default_ops).clone();

			// Update the opinion array - pairs of (key, score)
			for j in 0..NUM_NEIGHBOURS {
				let (pk_j, _) = self.set[j];

				// Conditions fro nullifying the score
				// 1. pk_j == 0 (Default key)
				// 2. pk_j == pk_i
				let is_pk_j_default = pk_j == Fr::zero();
				let is_pk_i = pk_j == pk_i;

				if is_pk_j_default || is_pk_i {
					ops_i[j] = Fr::zero();
				}
			}

			// Distribute the scores
			let op_score_sum = ops_i.iter().fold(Fr::zero(), |acc, &score| acc + score);
			if op_score_sum == Fr::zero() {
				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, _) = self.set[j];

					// Conditions for distributing the score
					// 1. pk_j != pk_i
					// 2. pk_j != 0 (Default key)
					let is_diff_pk = pk_j != pk_i;
					let is_not_default = pk_j != Fr::zero();

					if is_diff_pk && is_not_default {
						ops_i[j] = Fr::from(1);
					}
				}
			}
			filtered_ops.insert(pk_i, ops_i);
		}

		filtered_ops
	}

	/// Compute the EigenTrust score
	pub fn converge(&self) -> Vec<Fr> {
		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = self.set.iter().filter(|(pk, _)| *pk != Fr::zero()).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		// Prepare the opinion scores
		let mut ops = Vec::new();
		let filtered_ops: HashMap<Fr, Vec<Fr>> = self.filter_peers_ops();
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == Fr::zero() {
				ops.push(vec![Fr::zero(); NUM_NEIGHBOURS]);
			} else {
				let scores = filtered_ops.get(&pk).unwrap();
				ops.push(scores.clone());
			}
		}

		// Normalize the opinion scores
		let mut ops_norm = vec![vec![Fr::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		for i in 0..NUM_NEIGHBOURS {
			let op_score_sum: Fr = ops[i].iter().sum();
			let inverted_sum = op_score_sum.invert().unwrap_or(Fr::zero());

			for j in 0..NUM_NEIGHBOURS {
				let ops_ij = ops[i][j];
				ops_norm[i][j] = ops_ij * inverted_sum;
			}
		}

		// Compute the EigenTrust scores using the filtered and normalized scores
		let mut s: Vec<Fr> = self.set.iter().map(|(_, score)| score.clone()).collect();
		let mut new_s: Vec<Fr> = self.set.iter().map(|(_, score)| score.clone()).collect();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = Fr::zero();
				for j in 0..NUM_NEIGHBOURS {
					let score = ops_norm[j][i].clone() * s[j].clone();
					score_i_sum = score + score_i_sum;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}

		// Assert the score sum for checking the possible reputation leak
		let sum_initial = self.set.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
		let sum_final = s.iter().fold(Fr::zero(), |acc, &score| acc + score);
		assert!(sum_initial == sum_final);

		s
	}

	/// Compute the EigenTrust score using BigRational numbers
	pub fn converge_rational(&self) -> Vec<BigRational> {
		let mut filtered_ops: HashMap<Fr, Vec<Fr>> = self.filter_peers_ops();

		let mut ops = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == Fr::zero() {
				ops.push(vec![BigInt::zero(); NUM_NEIGHBOURS]);
			} else {
				let ops_i = filtered_ops.get_mut(&pk).unwrap();
				let scores =
					ops_i.iter().map(|&score| fe_to_big(score).to_bigint().unwrap()).collect();
				ops.push(scores);
			}
		}

		// Sanity check
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let init_score_bn = BigInt::from_u128(INITIAL_SCORE).unwrap();
		let mut s: Vec<BigRational> =
			vec![BigRational::from_integer(init_score_bn); NUM_NEIGHBOURS];

		let mut ops_norm = vec![vec![BigRational::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		for i in 0..NUM_NEIGHBOURS {
			let op_score_sum = ops[i].iter().fold(BigInt::zero(), |acc, score| acc + score);

			for j in 0..NUM_NEIGHBOURS {
				let score = ops[i][j].clone();
				ops_norm[i][j] = BigRational::new(score, op_score_sum.clone());
			}
		}

		let mut new_s = s.clone();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = BigRational::zero();
				for j in 0..NUM_NEIGHBOURS {
					let score = ops_norm[j][i].clone() * s[j].clone();
					score_i_sum = score + score_i_sum;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}
		s
	}

	// TODO: Scale the ratio to the standardised decimal position
	// TODO: Find `NUM_LIMBS` and `POWER_OF_TEN` for standardised decimal position
	/// Method for checking the threshold for a given score
	pub fn check_threshold<const NUM_LIMBS: usize, const POWER_OF_TEN: usize>(
		&self, score: Fr, ratio: BigRational, threshold: Fr,
	) -> ThresholdWitness<NUM_LIMBS> {
		let x = ratio;

		let num = x.numer();
		let den = x.denom();

		let num_decomposed =
			decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(num.to_biguint().unwrap());
		let den_decomposed =
			decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(den.to_biguint().unwrap());

		// Constraint checks - circuits should implement from this point
		let composed_num_f = compose_big_decimal_f::<Fr, NUM_LIMBS, POWER_OF_TEN>(num_decomposed);
		let composed_den_f = compose_big_decimal_f::<Fr, NUM_LIMBS, POWER_OF_TEN>(den_decomposed);
		let composed_den_f_inv = composed_den_f.invert().unwrap();
		let res_f = composed_num_f * composed_den_f_inv;
		assert!(res_f == score);

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let first_limb_num = *num_decomposed.last().unwrap();
		let first_limb_den = *den_decomposed.last().unwrap();
		let comp = first_limb_den * threshold;
		let is_bigger = first_limb_num >= comp;

		ThresholdWitness { threshold, is_bigger, num_decomposed, den_decomposed }
	}
}

#[cfg(test)]
mod test {
	use std::time::Instant;

	use super::*;
	use crate::{rns::compose_big_decimal, utils::fe_to_big};

	use halo2::halo2curves::{bn256::Fr, ff::PrimeField};
	use itertools::Itertools;
	use num_bigint::ToBigInt;
	use num_rational::BigRational;
	use rand::thread_rng;
	use secp256k1::{generate_keypair, PublicKey};

	const NUM_NEIGHBOURS: usize = 12;
	const NUM_ITERATIONS: usize = 10;
	const INITIAL_SCORE: u128 = 1000;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		sk: &SecretKey, pks: &[Fr], scores: &[Fr],
	) -> Vec<Option<SignedAttestation>> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);

		let sign = Secp256k1::signing_only();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i] == Fr::zero() {
				res.push(None)
			} else {
				let (about, key, value, message) = (pks[i], Fr::zero(), scores[i], Fr::zero());
				let attestation = AttestationFr::new(about, key, value, message);
				let msg = attestation.hash().to_bytes();
				let signature =
					sign.sign_ecdsa_recoverable(&Message::from_slice(msg.as_slice()).unwrap(), sk);
				let signed_attestation = SignedAttestation::new(attestation, signature);

				res.push(Some(signed_attestation));
			}
		}
		res
	}

	#[test]
	#[should_panic]
	fn test_add_member_in_initial_set() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (_sk, pk) = generate_keypair(rng);
		let pk = field_value_from_pub_key(&pk);

		set.add_member(pk);

		// Re-adding the member should panic
		set.add_member(pk);
	}

	#[test]
	#[should_panic]
	fn test_one_member_converge() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (_sk, pk) = generate_keypair(rng);
		let pk_fr = field_value_from_pub_key(&pk);

		set.add_member(pk_fr);

		set.converge();
	}

	#[test]
	fn test_add_two_members_without_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (_sk1, pk1) = generate_keypair(rng);
		let (_sk2, pk2) = generate_keypair(rng);

		let pk1 = field_value_from_pub_key(&pk1);
		let pk2 = field_value_from_pub_key(&pk2);

		set.add_member(pk1);
		set.add_member(pk2);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_one_opinion() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (sk1, pk1) = generate_keypair(rng);
		let (_sk2, pk2) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(INITIAL_SCORE);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);
		let pk3_fr = field_value_from_pub_key(&pk3);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk3, &pks, &scores);

		set.update_op(pk3, op3);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_two_opinions() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);
		let pk3_fr = field_value_from_pub_key(&pk3);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_3_ops_quit_1_member() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);
		let pk3_fr = field_value_from_pub_key(&pk3);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk3, &pks, &scores);

		set.update_op(pk3, op3);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2_fr);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_2_ops_quit_1_member_1_op() {
		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);
		let pk3_fr = field_value_from_pub_key(&pk3);

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

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

		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		let pk1_fr = field_value_from_pub_key(&pk1);
		let pk2_fr = field_value_from_pub_key(&pk2);
		let pk3_fr = field_value_from_pub_key(&pk3);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);
		scores[1] = Fr::from_u128(10);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[2] = Fr::from_u128(30);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk3, &pks, &scores);

		// Setup EigenTrustSet
		let mut eigen_trust_set =
			EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		eigen_trust_set.add_member(pk1_fr);
		eigen_trust_set.add_member(pk2_fr);
		eigen_trust_set.add_member(pk3_fr);

		eigen_trust_set.update_op(pk1, op1);
		eigen_trust_set.update_op(pk2, op2);
		eigen_trust_set.update_op(pk3, op3);

		let filtered_ops = eigen_trust_set.filter_peers_ops();

		let final_peers_count =
			eigen_trust_set.set.iter().filter(|&&(pk, _)| pk != Fr::zero()).count();
		let final_ops_count = filtered_ops.keys().count();
		assert!(final_peers_count == final_ops_count);
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
	>(
		ops: Vec<Vec<Fr>>,
	) -> (Vec<Fr>, Vec<BigRational>, Vec<ThresholdWitness<NUM_LIMBS>>) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let keys: Vec<(SecretKey, PublicKey)> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| generate_keypair(rng)).collect();
		let sks: Vec<SecretKey> = keys.iter().map(|(sk, _)| sk.clone()).collect();
		let pks: Vec<PublicKey> = keys.iter().map(|(_, pk)| pk.clone()).collect();

		// Add the publicKey to the set
		pks.iter().for_each(|pk| set.add_member(field_value_from_pub_key(&pk.clone())));

		let pks_fr: Vec<Fr> = pks.iter().map(|pk| field_value_from_pub_key(&pk.clone())).collect();

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();

			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&sks[i], &pks_fr, &scores,
			);

			let pk_i = pks[i];
			set.update_op(pk_i, op_i);
		}

		let s = set.converge();
		let s_ratios = set.converge_rational();

		let mut tws = Vec::new();
		let threshold = Fr::from_u128(435);
		for (&score, ratio) in s.iter().zip(s_ratios.clone()) {
			let tw = set.check_threshold::<NUM_LIMBS, POWER_OF_TEN>(score, ratio, threshold);
			tws.push(tw);
		}

		(s, s_ratios, tws)
	}

	#[test]
	fn test_scaling_1() {
		const NUM_NEIGHBOURS: usize = 10;
		const NUM_ITERATIONS: usize = 30;
		const INITIAL_SCORE: u128 = 1000;
		// Constants related to threshold check
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 50;

		let ops_raw = [
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
		];

		let ops = ops_raw.map(|arr| arr.map(|x| Fr::from_u128(x)).to_vec()).to_vec();

		let start = Instant::now();

		let (s, s_ratios, tws) = eigen_trust_set_testing_helper::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			NUM_LIMBS,
			POWER_OF_TEN,
		>(ops);

		let end = start.elapsed();
		println!("Convergence time: {:?}", end);

		let s_int: String = s_ratios.iter().map(|v| v.to_integer().to_str_radix(10)).join(", ");
		println!("NATIVE BIG_RATIONAL RESULT: [{}]", s_int);
		let s_formatted: Vec<String> = s.iter().map(|&x| fe_to_big(x).to_str_radix(10)).collect();
		println!("new s: {:#?}", s_formatted);
		for tw in tws {
			let num = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.num_decomposed);
			let den = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.den_decomposed);
			let ratio = BigRational::new(num.to_bigint().unwrap(), den.to_bigint().unwrap());
			println!(
				"real score: {:?}, is bigger than 435: {:?}",
				ratio.to_integer().to_str_radix(10),
				tw.is_bigger,
			);
		}
	}
}
