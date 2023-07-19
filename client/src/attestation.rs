//! # Attestation Module.
//!
//! This module deals with all attestations and AttestationStation related
//! data types and functionalities.

use crate::{
	att_station::{AttestationCreatedFilter, AttestationData as ContractAttestationData},
	eth::{address_from_public_key, scalar_from_address},
	NUM_BITS, NUM_LIMBS,
};
use eigen_trust_circuit::{
	dynamic_sets::ecdsa_native::AttestationFr,
	ecdsa::native::Signature,
	halo2::halo2curves::{bn256::Fr as Scalar, ff::FromUniformBytes, secp256k1::Secp256k1Affine},
	params::rns::secp256k1::Secp256k1_4_68,
};
use ethers::types::{Address, Bytes, Uint8, H160, H256};
use secp256k1::{
	ecdsa::{self, RecoverableSignature, RecoveryId},
	Message,
};

/// Domain prefix.
pub const DOMAIN_PREFIX: [u8; DOMAIN_PREFIX_LEN] = *b"eigen_trust_";
/// Domain prefix length.
pub const DOMAIN_PREFIX_LEN: usize = 12;
/// ECDSA public key
pub type ECDSAPublicKey = secp256k1::PublicKey;
/// ECDSA signature
pub type ECDSASignature = ecdsa::RecoverableSignature;
/// Signature represented with field elements
pub type SignatureFr = Signature<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68>;

/// Attestation struct.
#[derive(Clone, Debug, Default)]
pub struct AttestationEth {
	/// Ethereum address of peer being rated
	pub about: Address,
	/// Unique identifier for the action being rated
	pub domain: H160,
	/// Given rating for the action
	pub value: Uint8,
	/// Optional field for attaching additional information to the attestation
	pub message: H256,
}

impl AttestationEth {
	/// Constructs a new attestation struct.
	pub fn new(about: Address, domain: H160, value: Uint8, message: Option<H256>) -> Self {
		Self { about, domain, value, message: message.unwrap_or(H256::from([0u8; 32])) }
	}

	/// Constructs a new attestation struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, &'static str> {
		let attestation_val = log.val.to_vec();
		assert!(attestation_val.len() == 66 || attestation_val.len() == 98);

		let value = attestation_val[65];
		let mut message = [0; 32];
		message.copy_from_slice(&attestation_val[66..]);

		let mut domain = [0; 20];
		domain.copy_from_slice(&log.key[DOMAIN_PREFIX_LEN..]);

		Ok(Self {
			about: log.about,
			domain: H160::from(domain),
			value: Uint8::from(value),
			message: H256::from(message),
		})
	}

	/// Converts the attestation to the scalar representation.
	pub fn to_attestation_fr(&self) -> Result<AttestationFr, &'static str> {
		// About
		let about = scalar_from_address(&self.about)?;

		// Domain
		let mut domain_fixed = *self.domain.as_fixed_bytes();
		domain_fixed.reverse();

		let mut domain_extended_bytes = [0u8; 32];
		domain_extended_bytes[..20].copy_from_slice(&domain_fixed);

		let domain_fr_opt = Scalar::from_bytes(&domain_extended_bytes);
		let domain = if domain_fr_opt.is_some().into() {
			domain_fr_opt.unwrap()
		} else {
			return Err("Failed to convert key to scalar");
		};

		// Value
		let value = Scalar::from(u64::from(u8::from(self.value.clone())));

		// Message
		let mut message_fixed = *self.message.as_fixed_bytes();
		message_fixed.reverse();

		let mut message_bytes = [0u8; 64];
		message_bytes[..32].copy_from_slice(&message_fixed);

		let message = Scalar::from_uniform_bytes(&message_bytes);

		Ok(AttestationFr { about, domain, value, message })
	}

	/// Construct the key from the attestation domain
	/// TODO: change to fixed bytes type
	pub fn get_key(&self) -> H256 {
		let mut key = [0; 32];

		key[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
		key[DOMAIN_PREFIX_LEN..].copy_from_slice(self.domain.as_fixed_bytes());

		H256::from(key)
	}
}

impl From<AttestationRaw> for AttestationEth {
	fn from(att_raw: AttestationRaw) -> Self {
		let about_address = Address::from(att_raw.about);
		let domain_bytes = H160::from(att_raw.domain);
		let value_u8 = Uint8::from(att_raw.value);
		let message_bytes = H256::from(att_raw.message);

		AttestationEth {
			about: about_address,
			domain: domain_bytes,
			value: value_u8,
			message: message_bytes,
		}
	}
}

/// Attestation with eth types.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SignatureEth {
	/// The 'r' value of the ECDSA signature.
	sig_r: H256,
	/// The 's' value of the ECDSA signature.
	sig_s: H256,
	/// Recovery id of the ECDSA signature.
	rec_id: Uint8,
}

impl SignatureEth {
	/// Constructs a new signature struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, &'static str> {
		let attestation_val = log.val.to_vec();
		assert!(attestation_val.len() == 66 || attestation_val.len() == 98);

		let mut r = [0; 32];
		let mut s = [0; 32];
		r.copy_from_slice(&attestation_val[..32]);
		s.copy_from_slice(&attestation_val[32..64]);
		let rec_id = attestation_val[64];

		Ok(Self { sig_r: H256::from(r), sig_s: H256::from(s), rec_id: Uint8::from(rec_id) })
	}

	/// Converts a vector of bytes into the struct.
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, &'static str> {
		if bytes.len() != 65 {
			return Err("Input bytes vector should be of length 65");
		}

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];

		sig_r.copy_from_slice(&bytes[..32]);
		sig_s.copy_from_slice(&bytes[32..64]);
		let rec_id = bytes[64];

		Ok(
			Self {
				sig_r: H256::from(sig_r),
				sig_s: H256::from(sig_s),
				rec_id: Uint8::from(rec_id),
			},
		)
	}

	/// Converts the struct into a vector of bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(65);

		bytes.extend(self.sig_r.as_fixed_bytes());
		bytes.extend(self.sig_s.as_fixed_bytes());
		bytes.push(u8::from(self.rec_id.clone()));

		bytes
	}

	/// Get raw bytes
	pub fn get_raw_signature(&self) -> ([u8; 32], [u8; 32], u8) {
		let mut r = [0; 32];
		let mut s = [0; 32];
		r.copy_from_slice(self.sig_r.as_fixed_bytes());
		s.copy_from_slice(self.sig_s.as_fixed_bytes());

		let rec_id = u8::from(self.rec_id.clone());

		(r, s, rec_id)
	}
}

impl From<SignatureRaw> for SignatureEth {
	fn from(sig: SignatureRaw) -> Self {
		let sig_r = H256::from(sig.sig_r);
		let sig_s = H256::from(sig.sig_s);
		let rec_id = Uint8::from(sig.rec_id);

		Self { sig_r, sig_s, rec_id }
	}
}

/// Attestation submission struct
#[derive(Clone, Debug, Default)]
pub struct SignedAttestationEth {
	/// Attestation
	pub attestation: AttestationEth,
	/// Signature
	pub signature: SignatureEth,
}

impl SignedAttestationEth {
	/// Construct new signed attestations
	pub fn new(attestation: AttestationEth, signature: SignatureEth) -> Self {
		Self { attestation, signature }
	}

	/// Constructs a new signature struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, &'static str> {
		let attestation = AttestationEth::from_log(log)?;
		let signature = SignatureEth::from_log(log)?;

		Ok(Self { attestation, signature })
	}

	/// Recover the public key from the attestation signature
	pub fn recover_public_key(&self) -> Result<ECDSAPublicKey, &'static str> {
		let attestation = self.attestation.to_attestation_fr()?;
		let message_hash = attestation.hash().to_bytes();
		let signature_raw: SignatureRaw = self.signature.clone().into();
		let signature = RecoverableSignature::from(signature_raw);

		let public_key = signature
			.recover(&Message::from_slice(message_hash.as_slice()).unwrap())
			.map_err(|_| "Failed to recover public key")?;

		Ok(public_key)
	}

	/// Convert to payload bytes
	pub fn to_payload(&self) -> Bytes {
		let sig_bytes = self.signature.to_bytes();
		let value = u8::from(self.attestation.value.clone());
		let message = self.attestation.message.as_bytes();

		let mut bytes = Vec::new();
		bytes.extend(&sig_bytes);
		bytes.push(value);

		if message == [0; 32] {
			bytes.extend(message);
		}

		Bytes::from(bytes)
	}
}

impl From<SignedAttestationRaw> for SignedAttestationEth {
	fn from(sig_att: SignedAttestationRaw) -> Self {
		let attestation = AttestationEth::from(sig_att.attestation);
		let signature = SignatureEth::from(sig_att.signature);

		Self { attestation, signature }
	}
}

/// Attestation struct.
#[derive(Clone, Debug, Default)]
pub struct AttestationRaw {
	/// Ethereum address of peer being rated
	about: [u8; 20],
	/// Unique identifier for the action being rated
	domain: [u8; 20],
	/// Given rating for the action
	value: u8,
	/// Optional field for attaching additional information to the attestation
	message: [u8; 32],
}

impl AttestationRaw {
	/// Constructor for raw attestation
	pub fn new(about: [u8; 20], domain: [u8; 20], value: u8, message: [u8; 32]) -> Self {
		Self { about, domain, value, message }
	}
}

impl From<AttestationEth> for AttestationRaw {
	fn from(att_eth: AttestationEth) -> Self {
		let about = *att_eth.about.as_fixed_bytes();
		let domain = *att_eth.domain.as_fixed_bytes();
		let message = *att_eth.message.as_fixed_bytes();
		let value = u8::from(att_eth.value);

		Self { about, domain, value, message }
	}
}

/// Attestation raw data payload.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SignatureRaw {
	/// The 'r' value of the ECDSA signature.
	sig_r: [u8; 32],
	/// The 's' value of the ECDSA signature.
	sig_s: [u8; 32],
	/// Recovery id of the ECDSA signature.
	rec_id: u8,
}

impl SignatureRaw {
	/// Constructor for raw signature
	pub fn new(sig_r: [u8; 32], sig_s: [u8; 32], rec_id: u8) -> Self {
		Self { sig_r, sig_s, rec_id }
	}

	/// Gets the ECDSA recoverable signature.
	pub fn get_signature(&self) -> RecoverableSignature {
		let concat_sig = [self.sig_r, self.sig_s].concat();
		let recovery_id = RecoveryId::from_i32(i32::from(self.rec_id)).unwrap();

		RecoverableSignature::from_compact(concat_sig.as_slice(), recovery_id).unwrap()
	}
}

impl From<RecoverableSignature> for SignatureRaw {
	fn from(sig: RecoverableSignature) -> Self {
		let (rec_id, sig) = sig.serialize_compact();

		let mut sig_r = [0; 32];
		let mut sig_s = [0; 32];
		sig_r.copy_from_slice(&sig[..32]);
		sig_s.copy_from_slice(&sig[32..]);

		let rec_id = rec_id.to_i32() as u8;

		Self { sig_r, sig_s, rec_id }
	}
}

impl From<SignatureRaw> for RecoverableSignature {
	fn from(sig: SignatureRaw) -> Self {
		let concat_sig = [sig.sig_r, sig.sig_s].concat();
		let recovery_id = RecoveryId::from_i32(i32::from(sig.rec_id)).unwrap();

		RecoverableSignature::from_compact(concat_sig.as_slice(), recovery_id).unwrap()
	}
}

impl From<SignatureEth> for SignatureRaw {
	fn from(att_eth: SignatureEth) -> Self {
		let sig_r = *att_eth.sig_r.as_fixed_bytes();
		let sig_s = *att_eth.sig_s.as_fixed_bytes();
		let rec_id = u8::from(att_eth.rec_id);

		Self { sig_r, sig_s, rec_id }
	}
}

/// Attestation submission struct
#[derive(Clone, Debug, Default)]
pub struct SignedAttestationRaw {
	/// Attestation
	attestation: AttestationRaw,
	/// Signature
	signature: SignatureRaw,
}

impl SignedAttestationRaw {
	/// Constructor for signed attestations
	pub fn new(attestation: AttestationRaw, signature: SignatureRaw) -> Self {
		Self { attestation, signature }
	}
}

impl From<SignedAttestationEth> for SignedAttestationRaw {
	fn from(sign_att: SignedAttestationEth) -> Self {
		let attestation = AttestationRaw::from(sign_att.attestation);
		let signature = SignatureRaw::from(sign_att.signature);

		Self { attestation, signature }
	}
}

/// Recovers the signing Ethereum address from a signed attestation.
pub fn address_from_signed_att(
	signed_attestation: &SignedAttestationEth,
) -> Result<Address, &'static str> {
	// Get the signing key
	let public_key = signed_attestation.recover_public_key()?;

	// Get the address from the public key
	address_from_public_key(&public_key)
}

/// Constructs the contract attestation data from a signed attestation.
/// The return of this function is the actual data stored on the contract.
pub fn att_data_from_signed_att(
	signed_attestation: &SignedAttestationEth,
) -> Result<ContractAttestationData, &'static str> {
	// Recover the about Ethereum address from the signed attestation
	let mut about_bytes = signed_attestation.attestation.about.as_bytes().to_vec();
	about_bytes.reverse();

	let address = Address::from_slice(&about_bytes[12..]);

	// Get the attestation key
	let mut key = [0; 32];
	key[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
	key[DOMAIN_PREFIX_LEN..]
		.copy_from_slice(signed_attestation.attestation.domain.as_fixed_bytes());

	let payload = signed_attestation.to_payload();

	Ok(ContractAttestationData(address, key, payload))
}

// #[cfg(test)]
// mod tests {
// 	use crate::attestation::*;
// 	use ethers::{
// 		prelude::k256::ecdsa::SigningKey,
// 		signers::{Signer, Wallet},
// 		types::Bytes,
// 	};
// 	use secp256k1::{ecdsa::RecoveryId, Message, Secp256k1, SecretKey};

// 	#[test]
// 	fn test_attestation_to_scalar_att() {
// 		// Build key
// 		let domain_input = [
// 			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
// 			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
// 		];

// 		let mut key_bytes: [u8; 32] = [0; 32];
// 		key_bytes[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
// 		key_bytes[DOMAIN_PREFIX_LEN..].copy_from_slice(&domain_input);

// 		// Message input
// 		let mut message = [
// 			0xff, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
// 			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
// 			0x65, 0x6e, 0x79, 0xff,
// 		];

// 		// Address Input
// 		let mut address = [
// 			0xff, 0x47, 0x73, 0x4b, 0x6b, 0x42, 0x6e, 0x59, 0x61, 0x4c, 0x71, 0x4a, 0x45, 0x76,
// 			0x79, 0x4c, 0x6a, 0x73, 0x46, 0xff,
// 		];

// 		let attestation = AttestationEth::new(
// 			Address::from(address),
// 			Bytes::from(key_bytes),
// 			Uint8::from(10),
// 			Some(H256::from(message)),
// 		);

// 		let attestation_fr = attestation.to_attestation_fr().unwrap();

// 		// Expected about
// 		let mut expected_about_input = [0u8; 32];
// 		address.reverse();
// 		expected_about_input[..20].copy_from_slice(&address);
// 		let expected_about = Scalar::from_bytes(&expected_about_input).unwrap();

// 		// Expected domain
// 		let mut expected_domain_input = [0u8; 32];
// 		expected_domain_input[DOMAIN_PREFIX_LEN..].copy_from_slice(&domain_input);
// 		expected_domain_input.reverse();
// 		let expected_domain = Scalar::from_bytes(&expected_domain_input).unwrap();

// 		// Expected value
// 		let expected_value = Scalar::from(10u64);

// 		// Expected message
// 		let mut expected_message_input = [0u8; 64];
// 		message.reverse();

// 		expected_message_input[..32].copy_from_slice(&message);
// 		let expected_message = Scalar::from_uniform_bytes(&expected_message_input);

// 		assert_eq!(attestation_fr.about, expected_about);
// 		assert_eq!(attestation_fr.domain, expected_domain);
// 		assert_eq!(attestation_fr.value, expected_value);
// 		assert_eq!(attestation_fr.message, expected_message);
// 	}

// 	#[test]
// 	fn test_attestation_payload_from_signed_att() {
// 		let secp = Secp256k1::new();
// 		let secret_key_as_bytes = [0x40; 32];
// 		let secret_key = SecretKey::from_slice(&secret_key_as_bytes).unwrap();

// 		let attestation = AttestationFr {
// 			about: Scalar::zero(),
// 			domain: Scalar::zero(),
// 			value: Scalar::zero(),
// 			message: Scalar::zero(),
// 		};

// 		let message = attestation.hash().to_bytes();

// 		let signature = secp.sign_ecdsa_recoverable(
// 			&Message::from_slice(message.as_slice()).unwrap(),
// 			&secret_key,
// 		);
// 		SignatureEth::from(signature);

// 		let signed_attestation = SignedAttestationEth::new(attestation, signature);

// 		// Convert the signed attestation to attestation payload
// 		let attestation_payload = signed_attestation.to_payload();

// 		// Check the attestation payload
// 		let (recid, sig) = signed_attestation.signature.get_signature().serialize_compact();
// 		let mut payload_bytes = sig.to_vec();
// 		payload_bytes.push(recid.to_i32() as u8);
// 		payload_bytes.push(sig)
// 	}

// 	#[test]
// 	fn test_attestation_payload_to_signed_att() {
// 		let secp = Secp256k1::new();
// 		let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
// 		let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

// 		let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);

// 		let (recovery_id, serialized_sig) = signature.serialize_compact();

// 		let mut sig_r = [0u8; 32];
// 		let mut sig_s = [0u8; 32];
// 		sig_r.copy_from_slice(&serialized_sig[0..32]);
// 		sig_s.copy_from_slice(&serialized_sig[32..64]);

// 		let payload = AttestationRaw {
// 			sig_r,
// 			sig_s,
// 			rec_id: recovery_id.to_i32() as u8,
// 			value: 5,
// 			message: [3u8; 32],
// 		};

// 		let sig = payload.get_signature();

// 		assert_eq!(
// 			sig.serialize_compact().0,
// 			RecoveryId::from_i32(payload.rec_id as i32).unwrap()
// 		);
// 		assert_eq!(
// 			sig.serialize_compact().1.as_slice(),
// 			[payload.sig_r, payload.sig_s].concat().as_slice()
// 		);
// 	}

// 	#[test]
// 	fn test_attestation_payload_bytes_to_struct_and_back() {
// 		let payload = AttestationRaw {
// 			sig_r: [0u8; 32],
// 			sig_s: [0u8; 32],
// 			rec_id: 0,
// 			value: 10,
// 			message: [0u8; 32],
// 		};

// 		let bytes = payload.to_bytes();

// 		let result_payload = AttestationRaw::from_bytes(bytes).unwrap();

// 		assert_eq!(payload, result_payload);
// 	}

// 	#[test]
// 	fn test_attestation_payload_from_bytes_error_handling() {
// 		let bytes = vec![0u8; 99];
// 		let result = AttestationRaw::from_bytes(bytes);
// 		assert!(result.is_err());
// 	}

// 	#[test]
// 	fn test_address_from_signed_att() {
// 		let secp = Secp256k1::new();

// 		let secret_key_as_bytes = [0xcd; 32];

// 		let secret_key =
// 			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");

// 		let attestation = AttestationFr {
// 			about: Scalar::zero(),
// 			domain: Scalar::zero(),
// 			value: Scalar::zero(),
// 			message: Scalar::zero(),
// 		};

// 		let message = attestation.hash().to_bytes();

// 		let signature = secp.sign_ecdsa_recoverable(
// 			&Message::from_slice(message.as_slice()).unwrap(),
// 			&secret_key,
// 		);

// 		let signed_attestation = SignedAttestation { attestation, signature };

// 		// Replace with expected address
// 		let expected_address =
// 			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref()).unwrap()).address();

// 		assert_eq!(
// 			address_from_signed_att(&signed_attestation).unwrap(),
// 			expected_address
// 		);
// 	}

// 	#[test]
// 	fn test_contract_att_data_from_signed_att() {
// 		let secp = Secp256k1::new();
// 		let secret_key_as_bytes = [0x40; 32];
// 		let secret_key =
// 			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");
// 		let about_bytes = [
// 			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
// 			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
// 		];
// 		// Build key
// 		let domain_input = [
// 			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
// 			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
// 		];

// 		let mut key_bytes: [u8; 32] = [0; 32];
// 		key_bytes[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
// 		key_bytes[DOMAIN_PREFIX_LEN..].copy_from_slice(&domain_input);

// 		// Message input
// 		let message = [
// 			0xff, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
// 			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
// 			0x65, 0x6e, 0x79, 0xff,
// 		];

// 		let attestation = AttestationEth::new(
// 			Address::from(about_bytes),
// 			H256::from(key_bytes),
// 			10,
// 			Some(H256::from(message)),
// 		);

// 		let attestation_fr = attestation.to_attestation_fr().unwrap();

// 		let message = attestation_fr.hash().to_bytes();

// 		let signature = secp.sign_ecdsa_recoverable(
// 			&Message::from_slice(message.as_slice()).unwrap(),
// 			&secret_key,
// 		);

// 		let signed_attestation = SignedAttestation { attestation: attestation_fr, signature };

// 		let contract_att_data = att_data_from_signed_att(&signed_attestation).unwrap();

// 		let expected_address = Address::from(about_bytes);
// 		assert_eq!(contract_att_data.0, expected_address);

// 		let mut expected_key = signed_attestation.attestation.domain.to_bytes();

// 		// Reverse and add domain
// 		expected_key.reverse();
// 		expected_key[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);

// 		assert_eq!(contract_att_data.1, expected_key);

// 		let expected_payload: Bytes =
// 			AttestationRaw::from_signed_attestation(&signed_attestation).unwrap().to_bytes().into();
// 		assert_eq!(contract_att_data.2, expected_payload);
// 	}
// }
