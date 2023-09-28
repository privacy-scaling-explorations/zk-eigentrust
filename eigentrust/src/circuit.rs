//! # Circuit Module.
//!
//! This module provides types and utilities for the circuits.

use crate::{attestation::SignedAttestationScalar, error::EigenError};
use eigentrust_zk::{
	circuits::{ECDSAPublicKey, RationalScore, Threshold4},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use ethers::types::Address;

// Re export eigentrust and threshold KZG params constants.
pub use eigentrust_zk::circuits::{ET_PARAMS_K, TH_PARAMS_K};

/// Scalar length in bytes.
pub const SCALAR_LEN: usize = 32;
/// Outbound local trust vector.
pub type OpinionVector = Vec<Option<SignedAttestationScalar>>;

/// Circuits.
pub enum Circuit {
	/// Eigentrust circuit
	EigenTrust,
	/// Threshold circuit
	Threshold,
}

impl Circuit {
	/// Converts to static string.
	pub fn as_str(&self) -> &'static str {
		match self {
			Circuit::EigenTrust => "et",
			Circuit::Threshold => "th",
		}
	}
}

/// Scores report struct.
pub struct ScoresReport {
	/// Participants' scores
	pub scores: Vec<Score>,
	/// Verifier public inputs
	pub pub_inputs: ETPublicInputs,
	/// Proof
	pub proof: Vec<u8>,
}

/// Score struct.
pub struct Score {
	/// Participant address.
	pub address: [u8; 20],
	/// Scalar score.
	pub score_fr: [u8; 32],
	/// Rational score (numerator, denominator).
	pub score_rat: ([u8; 32], [u8; 32]),
	/// Hexadecimal score.
	pub score_hex: [u8; 32],
}

/// EigenTrust circuit setup parameters
pub struct ETSetup {
	/// Ethereum addresses set.
	pub address_set: Vec<Address>,
	/// Attestation matrix.
	pub attestation_matrix: Vec<Vec<Option<SignedAttestationScalar>>>,
	/// ECDSA public keys set.
	pub ecdsa_set: Vec<Option<ECDSAPublicKey>>,
	/// Public inputs.
	pub pub_inputs: ETPublicInputs,
	/// Rational scores.
	pub rational_scores: Vec<RationalScore>,
}

impl ETSetup {
	/// Constructs a new ETSetup instance.
	pub fn new(
		address_set: Vec<Address>, attestation_matrix: Vec<Vec<Option<SignedAttestationScalar>>>,
		ecdsa_set: Vec<Option<ECDSAPublicKey>>, pub_inputs: ETPublicInputs,
		rational_scores: Vec<RationalScore>,
	) -> Self {
		Self { address_set, attestation_matrix, ecdsa_set, pub_inputs, rational_scores }
	}
}

/// Eigentrust circuit public input parameters
pub struct ETPublicInputs {
	/// Participants' set
	pub participants: Vec<Scalar>,
	/// Participants' scores
	pub scores: Vec<Scalar>,
	/// Domain
	pub domain: Scalar,
	/// Opinions' hash
	pub opinion_hash: Scalar,
}

impl ETPublicInputs {
	/// Creates a new ETPublicInputs instance.
	pub fn new(
		participants: Vec<Scalar>, scores: Vec<Scalar>, domain: Scalar, opinion_hash: Scalar,
	) -> Self {
		Self { participants, scores, domain, opinion_hash }
	}

	/// Returns the struct as a concatenated Vec<Scalar>.
	pub fn to_vec(&self) -> Vec<Scalar> {
		let mut result = Vec::new();
		result.extend(self.participants.iter().cloned());
		result.extend(self.scores.iter().cloned());
		result.push(self.domain);
		result.push(self.opinion_hash);

		result
	}

	/// Returns the struct as a concatenated Vec<u8>.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut result = Vec::new();
		result.extend(self.participants.iter().flat_map(|s| s.to_bytes()));
		result.extend(self.scores.iter().flat_map(|s| s.to_bytes()));
		result.extend(self.domain.to_bytes());
		result.extend(self.opinion_hash.to_bytes());

		result
	}

	/// Creates a new ETPublicInputs instance from a Vec<u8>.
	pub fn from_bytes(bytes: Vec<u8>, participants: usize) -> Result<Self, EigenError> {
		// Check if the length of bytes matches the expected length.
		if bytes.len() != (2 * participants + 2) * SCALAR_LEN {
			return Err(EigenError::ParsingError(
				"Invalid bytes length.".to_string(),
			));
		}

		// Build participants.
		let participants_vec =
			(0..participants).map(|i| get_scalar_at(&bytes, i)).collect::<Result<Vec<_>, _>>()?;

		// Build scores.
		let scores_vec = (participants..2 * participants)
			.map(|i| get_scalar_at(&bytes, i))
			.collect::<Result<Vec<_>, _>>()?;

		// Build domain and opinion hash.
		let domain = get_scalar_at(&bytes, 2 * participants)?;
		let opinion_hash = get_scalar_at(&bytes, 2 * participants + 1)?;

		Ok(Self::new(
			participants_vec, scores_vec, domain, opinion_hash,
		))
	}
}

/// Threshold circuit setup parameters.
pub struct ThSetup {
	/// Threshold circuit.
	pub circuit: Threshold4,
	/// Public inputs.
	pub pub_inputs: ThPublicInputs,
}

impl ThSetup {
	/// Creates a new ThSetup instance.
	pub fn new(circuit: Threshold4, pub_inputs: ThPublicInputs) -> Self {
		Self { circuit, pub_inputs }
	}
}

/// Threshold circuit report.
pub struct ThReport {
	/// Proof.
	pub proof: Vec<u8>,
	/// Verifier public inputs.
	pub pub_inputs: ThPublicInputs,
}

/// Threshold circuit public input parameters.
pub struct ThPublicInputs {
	/// Participant address.
	pub address: Scalar,
	/// Threshold value.
	pub threshold: Scalar,
	/// Native threshold check.
	pub th_check: Scalar,
	/// Native aggregator instances.
	pub instances: Vec<Scalar>,
}

impl ThPublicInputs {
	/// Creates a new ThPublicInputs instance.
	pub fn new(
		address: Scalar, threshold: Scalar, th_check: Scalar, instances: Vec<Scalar>,
	) -> Self {
		Self { address, threshold, th_check, instances }
	}

	/// Returns the struct as a concatenated Vec<Scalar>.
	pub fn to_vec(&self) -> Vec<Scalar> {
		let mut result = Vec::new();
		result.push(self.address);
		result.push(self.threshold);
		result.push(self.th_check);
		result.extend(self.instances.iter().cloned());

		result
	}

	/// Returns the struct as a concatenated Vec<u8>.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut result = Vec::new();
		result.extend(self.address.to_bytes());
		result.extend(self.threshold.to_bytes());
		result.extend(self.th_check.to_bytes());
		result.extend(self.instances.iter().flat_map(|s| s.to_bytes()));

		result
	}

	/// Creates a new ThPublicInputs instance from a Vec<u8>.
	pub fn from_bytes(bytes: Vec<u8>, instances_count: usize) -> Result<Self, EigenError> {
		if bytes.len() != (instances_count + 3) * SCALAR_LEN {
			return Err(EigenError::ParsingError(
				"Invalid bytes length.".to_string(),
			));
		}

		let address = get_scalar_at(&bytes, 0)?;
		let threshold = get_scalar_at(&bytes, 1)?;
		let th_check = get_scalar_at(&bytes, 2)?;

		let instances_vec = (3..3 + instances_count)
			.map(|i| get_scalar_at(&bytes, i))
			.collect::<Result<Vec<_>, _>>()?;

		Ok(Self::new(address, threshold, th_check, instances_vec))
	}
}

/// Gets a Scalar from a byte slice at a given index.
fn get_scalar_at(bytes: &[u8], index: usize) -> Result<Scalar, EigenError> {
	let start = index * SCALAR_LEN;
	let slice = &bytes[start..start + SCALAR_LEN];

	// Convert the slice into an array reference
	let array_ref: &[u8; 32] = slice
		.try_into()
		.map_err(|_| EigenError::ParsingError("Failed to convert slice into array".to_string()))?;

	// Convert bytes into a scalar
	let scalar_opt = Scalar::from_bytes(array_ref);

	if scalar_opt.is_some().into() {
		Ok(scalar_opt.unwrap())
	} else {
		Err(EigenError::ParsingError(
			"Failed to construct scalar from bytes".to_string(),
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use eigentrust_zk::halo2::arithmetic::Field;

	#[test]
	fn test_et_public_inputs_new() {
		let scalar = Scalar::random(&mut rand::thread_rng());

		let inputs = ETPublicInputs::new(
			vec![scalar.clone()],
			vec![scalar.clone()],
			scalar.clone(),
			scalar,
		);

		assert_eq!(inputs.participants.len(), 1);
		assert_eq!(inputs.scores.len(), 1);
	}

	#[test]
	fn test_et_public_inputs_to_vec() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(
			vec![scalar.clone()],
			vec![scalar.clone()],
			scalar.clone(),
			scalar.clone(),
		);

		let vec_representation = inputs.to_vec();

		assert_eq!(vec_representation.len(), 4);
		assert_eq!(vec_representation[0], scalar);
		assert_eq!(vec_representation[1], scalar);
		assert_eq!(vec_representation[2], scalar);
		assert_eq!(vec_representation[3], scalar);
	}

	#[test]
	fn test_et_public_inputs_to_bytes() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(
			vec![scalar.clone()],
			vec![scalar.clone()],
			scalar.clone(),
			scalar.clone(),
		);

		let bytes_representation = inputs.to_bytes();

		assert_eq!(bytes_representation.len(), 4 * 32);
	}

	#[test]
	fn test_et_public_inputs_from_bytes() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(
			vec![scalar.clone()],
			vec![scalar.clone()],
			scalar.clone(),
			scalar.clone(),
		);

		let bytes_representation = inputs.to_bytes();

		let reconstructed_inputs = ETPublicInputs::from_bytes(bytes_representation, 1).unwrap();

		assert_eq!(inputs.participants, reconstructed_inputs.participants);
		assert_eq!(inputs.scores, reconstructed_inputs.scores);
		assert_eq!(inputs.domain, reconstructed_inputs.domain);
		assert_eq!(inputs.opinion_hash, reconstructed_inputs.opinion_hash);
	}

	#[test]
	fn test_invalid_byte_length() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(
			vec![scalar.clone()],
			vec![scalar.clone()],
			scalar.clone(),
			scalar.clone(),
		);
		let mut bytes_representation = inputs.to_bytes();

		// Remove some bytes to make it invalid
		bytes_representation.pop();

		let result = ETPublicInputs::from_bytes(bytes_representation, 1);
		assert!(result.is_err());
	}

	#[test]
	fn test_multiple_participants() {
		let scalar1 = Scalar::random(&mut rand::thread_rng());
		let scalar2 = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(
			vec![scalar1.clone(), scalar2.clone()],
			vec![scalar1.clone(), scalar2.clone()],
			scalar1.clone(),
			scalar2.clone(),
		);

		let bytes_representation = inputs.to_bytes();
		let reconstructed_inputs = ETPublicInputs::from_bytes(bytes_representation, 2).unwrap();

		assert_eq!(inputs.participants, reconstructed_inputs.participants);
		assert_eq!(inputs.scores, reconstructed_inputs.scores);
	}

	#[test]
	fn test_empty_vectors() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ETPublicInputs::new(vec![], vec![], scalar.clone(), scalar.clone());

		let bytes_representation = inputs.to_bytes();
		let reconstructed_inputs = ETPublicInputs::from_bytes(bytes_representation, 0).unwrap();

		assert!(reconstructed_inputs.participants.is_empty());
		assert!(reconstructed_inputs.scores.is_empty());
	}

	#[test]
	fn test_invalid_scalar_byte_construction() {
		let invalid_bytes = vec![0u8; 128];

		let result = ETPublicInputs::from_bytes(invalid_bytes, 2);
		assert!(result.is_err());
	}

	#[test]
	fn test_th_public_inputs_new() {
		let scalar = Scalar::random(&mut rand::thread_rng());

		let inputs = ThPublicInputs::new(
			scalar.clone(),
			scalar.clone(),
			scalar.clone(),
			vec![scalar.clone(), scalar.clone()],
		);

		assert_eq!(inputs.instances.len(), 2);
	}

	#[test]
	fn test_th_public_inputs_to_vec() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ThPublicInputs::new(
			scalar.clone(),
			scalar.clone(),
			scalar.clone(),
			vec![scalar.clone(), scalar.clone()],
		);

		let vec_representation = inputs.to_vec();

		assert_eq!(vec_representation.len(), 5);
		assert_eq!(vec_representation[0], scalar);
		assert_eq!(vec_representation[1], scalar);
		assert_eq!(vec_representation[2], scalar);
		assert_eq!(vec_representation[3], scalar);
		assert_eq!(vec_representation[4], scalar);
	}

	#[test]
	fn test_th_public_inputs_to_bytes() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ThPublicInputs::new(
			scalar.clone(),
			scalar.clone(),
			scalar.clone(),
			vec![scalar.clone(), scalar.clone()],
		);

		let bytes_representation = inputs.to_bytes();

		assert_eq!(bytes_representation.len(), 5 * 32);
	}

	#[test]
	fn test_th_public_inputs_from_bytes() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ThPublicInputs::new(
			scalar.clone(),
			scalar.clone(),
			scalar.clone(),
			vec![scalar.clone(), scalar.clone()],
		);

		let bytes_representation = inputs.to_bytes();
		let reconstructed_inputs = ThPublicInputs::from_bytes(bytes_representation, 2).unwrap();

		assert_eq!(inputs.address, reconstructed_inputs.address);
		assert_eq!(inputs.threshold, reconstructed_inputs.threshold);
		assert_eq!(inputs.th_check, reconstructed_inputs.th_check);
		assert_eq!(inputs.instances, reconstructed_inputs.instances);
	}

	#[test]
	fn test_invalid_byte_length_th() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ThPublicInputs::new(
			scalar.clone(),
			scalar.clone(),
			scalar.clone(),
			vec![scalar.clone(), scalar.clone()],
		);
		let mut bytes_representation = inputs.to_bytes();

		// Remove some bytes to make it invalid
		bytes_representation.pop();

		let result = ThPublicInputs::from_bytes(bytes_representation, 2);
		assert!(result.is_err());
	}

	#[test]
	fn test_empty_instances() {
		let scalar = Scalar::random(&mut rand::thread_rng());
		let inputs = ThPublicInputs::new(scalar.clone(), scalar.clone(), scalar.clone(), vec![]);

		let bytes_representation = inputs.to_bytes();
		let reconstructed_inputs = ThPublicInputs::from_bytes(bytes_representation, 0).unwrap();

		assert!(reconstructed_inputs.instances.is_empty());
	}

	#[test]
	fn test_invalid_scalar_byte_construction_th() {
		let invalid_bytes = vec![0u8; 128];

		let result = ThPublicInputs::from_bytes(invalid_bytes, 4);
		assert!(result.is_err());
	}
}
