use crate::circuit::{PoseidonNativeHasher, PoseidonNativeSponge};

use halo2::halo2curves::{bn256::Fr, ff::PrimeField};
use secp256k1::{ecdsa, Message};
use std::collections::HashMap;

/// ECDSA public key
pub type ECDSAPublicKey = secp256k1::PublicKey;
/// ECDSA signature
pub type ECDSASignature = ecdsa::RecoverableSignature;

/// Attestation submission struct
#[derive(Clone)]
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

/// Attestation struct
#[derive(Clone, Debug)]
pub struct AttestationFr {
	/// Ethereum address of peer being rated
	pub about: Fr,
	/// Unique identifier for the action being rated
	pub key: Fr,
	/// Given rating for the action
	pub value: Fr,
	/// Optional field for attaching additional information to the attestation
	pub message: Fr,
}

impl AttestationFr {
	/// Construct a new attestation struct
	pub fn new(about: Fr, key: Fr, value: Fr, message: Fr) -> Self {
		Self { about, key, value, message }
	}

	/// Hash attestation
	pub fn hash(&self) -> Fr {
		PoseidonNativeHasher::new([self.about, self.key, self.value, self.message, Fr::zero()])
			.permute()[0]
	}
}

/// Dynamic set for EigenTrust
pub struct EigenTrustAttestationSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
> {
	set: Vec<(Option<ECDSAPublicKey>, Fr)>,
	ops: HashMap<ECDSAPublicKey, Vec<Fr>>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITERATIONS: usize, const INITIAL_SCORE: u128>
	EigenTrustAttestationSet<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>
{
	/// Constructs new instance
	pub fn new() -> Self {
		Self { set: Vec::new(), ops: HashMap::new() }
	}

	/// Add new set member and initial score
	pub fn add_member(&mut self, pk: ECDSAPublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == Some(pk));
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x.is_none());
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		self.set[index] = (Some(pk), initial_score);
	}

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: ECDSAPublicKey) {
		let pos = self.set.iter().position(|&(x, _)| x == Some(pk));
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (None, Fr::zero());

		self.ops.remove(&pk);
	}

	/// Update the opinion of the member
	pub fn update_op(&mut self, from: ECDSAPublicKey, op: Vec<SignedAttestation>) -> Fr {
		let pos_from = self.set.iter().position(|&(x, _)| x == Some(from));
		assert!(pos_from.is_some());

		let mut scores = vec![Fr::zero(); NUM_NEIGHBOURS];
		let mut hashes = Vec::new();
		for (i, att) in op.iter().enumerate() {
			// TODO: What is relation between `Fr` and `ECDSAPublickey`?
			// assert!(att.attestation.about == self.set[i].0);

			let recovered = att.recover_public_key().unwrap();
			assert!(recovered == from);

			scores[i] = att.attestation.value;

			let hash = att.attestation.hash();
			hashes.push(hash);
		}

		self.ops.insert(from, scores);

		let mut sponge_hasher = PoseidonNativeSponge::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		return op_hash;
	}
}
