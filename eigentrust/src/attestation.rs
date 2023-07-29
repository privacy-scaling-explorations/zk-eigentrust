//! # Attestation Module.
//!
//! This module deals with all attestations and AttestationStation related
//! data types and functionalities.

use crate::{
	att_station::AttestationCreatedFilter,
	error::EigenError,
	eth::{address_from_public_key, scalar_from_address},
	NUM_BITS, NUM_LIMBS,
};
use eigentrust_zk::{
	circuits::dynamic_sets::ecdsa_native::{
		Attestation as AttestationFr, SignedAttestation as SignedAttestationFr,
	},
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationEth {
	/// Ethereum address of peer being rated
	pub(crate) about: Address,
	/// Unique identifier for the action being rated
	pub(crate) domain: H160,
	/// Given rating for the action
	pub(crate) value: Uint8,
	/// Optional field for attaching additional information to the attestation
	pub(crate) message: H256,
}

impl AttestationEth {
	/// Constructs a new attestation struct.
	pub fn new(about: Address, domain: H160, value: Uint8, message: Option<H256>) -> Self {
		Self { about, domain, value, message: message.unwrap_or(H256::from([0u8; 32])) }
	}

	/// Constructs a new attestation struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, EigenError> {
		let attestation_val = log.val.to_vec();
		if attestation_val.len() != 66 && attestation_val.len() != 98 {
			return Err(EigenError::ConversionError(
				"Input bytes vector 'val' should be of length 66 or 98".to_string(),
			));
		}

		let value = attestation_val[65];

		let mut message = [0; 32];
		if attestation_val.len() > 66 {
			message.copy_from_slice(&attestation_val[66..]);
		};

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
	pub fn to_attestation_fr(&self) -> Result<AttestationFr, EigenError> {
		// About
		let about = scalar_from_address(&self.about)?;

		// Domain
		let mut domain_fixed = *self.domain.as_fixed_bytes();
		domain_fixed.reverse();

		let mut domain_extended_bytes = [0u8; 32];
		domain_extended_bytes[..20].copy_from_slice(&domain_fixed);

		let domain_fr_opt = Scalar::from_bytes(&domain_extended_bytes);
		let domain = match domain_fr_opt.is_some().into() {
			true => domain_fr_opt.unwrap(),
			false => {
				return Err(EigenError::ParsingError(
					"Failed to convert key to scalar".to_string(),
				));
			},
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
	pub(crate) sig_r: H256,
	/// The 's' value of the ECDSA signature.
	pub(crate) sig_s: H256,
	/// Recovery id of the ECDSA signature.
	pub(crate) rec_id: Uint8,
}

impl SignatureEth {
	/// Constructs a new signature struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, EigenError> {
		let attestation_val = log.val.to_vec();
		if attestation_val.len() != 66 && attestation_val.len() != 98 {
			return Err(EigenError::ConversionError(
				"Input bytes vector 'val' should be of length 66 or 98".to_string(),
			));
		}

		let mut r = [0; 32];
		let mut s = [0; 32];
		r.copy_from_slice(&attestation_val[..32]);
		s.copy_from_slice(&attestation_val[32..64]);
		let rec_id = attestation_val[64];

		Ok(Self { sig_r: H256::from(r), sig_s: H256::from(s), rec_id: Uint8::from(rec_id) })
	}

	/// Convert the struct into Fr version
	pub fn to_signature_fr(&self) -> SignatureFr {
		let sig_r = *self.sig_r.as_fixed_bytes();
		let sig_s = *self.sig_s.as_fixed_bytes();
		SignatureFr::from((sig_r, sig_s))
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
	pub(crate) attestation: AttestationEth,
	/// Signature
	pub(crate) signature: SignatureEth,
}

impl SignedAttestationEth {
	/// Construct new signed attestations
	pub fn new(attestation: AttestationEth, signature: SignatureEth) -> Self {
		Self { attestation, signature }
	}

	/// Recover the public key from the attestation signature
	pub fn recover_public_key(&self) -> Result<ECDSAPublicKey, EigenError> {
		let attestation = self.attestation.to_attestation_fr()?;
		let message_hash = attestation.hash().to_bytes();
		let signature_raw: SignatureRaw = self.signature.clone().into();
		let signature = RecoverableSignature::from(signature_raw);

		let public_key = signature
			.recover(&Message::from_slice(message_hash.as_slice()).unwrap())
			.map_err(|_| EigenError::RecoveryError("Failed to recover public key".to_string()))?;

		Ok(public_key)
	}

	/// Convert to payload bytes
	pub fn to_payload(&self) -> Bytes {
		let sig_raw: SignatureRaw = self.signature.clone().into();
		let sig_bytes = sig_raw.to_bytes();

		let value = u8::from(self.attestation.value.clone());
		let message = self.attestation.message.as_bytes();

		let mut bytes = Vec::new();
		bytes.extend(&sig_bytes);
		bytes.push(value);

		if message != [0; 32] {
			bytes.extend(message);
		}

		Bytes::from(bytes)
	}

	/// Constructs a new signature struct from an attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Result<Self, EigenError> {
		let attestation = AttestationEth::from_log(log)?;
		let signature = SignatureEth::from_log(log)?;

		Ok(Self { attestation, signature })
	}

	/// Converts the structure into data needed for AttestationStation
	pub fn to_tx_data(&self) -> Result<(Address, Address, H256, Bytes), EigenError> {
		let payload = self.to_payload();
		let key = self.attestation.get_key();
		let pk = self.recover_public_key()?;
		let attestor = address_from_public_key(&pk);
		let attested = self.attestation.about;

		Ok((attestor, attested, key, payload))
	}

	/// Convert to a struct with field values
	pub fn to_signed_signature_fr(&self) -> Result<SignedAttestationFr, EigenError> {
		let attestation_fr = self.attestation.to_attestation_fr()?;
		let signature_fr = self.signature.to_signature_fr();
		Ok(SignedAttestationFr::new(attestation_fr, signature_fr))
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationRaw {
	/// Ethereum address of peer being rated
	pub(crate) about: [u8; 20],
	/// Unique identifier for the action being rated
	pub(crate) domain: [u8; 20],
	/// Given rating for the action
	pub(crate) value: u8,
	/// Optional field for attaching additional information to the attestation
	pub(crate) message: [u8; 32],
}

impl AttestationRaw {
	/// Constructor for raw attestation
	pub fn new(about: [u8; 20], domain: [u8; 20], value: u8, message: [u8; 32]) -> Self {
		Self { about, domain, value, message }
	}

	/// Converts a vector of bytes into the struct.
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EigenError> {
		if bytes.len() != 73 {
			return Err(EigenError::ConversionError(
				"Input bytes vector should be of length 73".to_string(),
			));
		}

		let mut about = [0u8; 20];
		let mut domain = [0u8; 20];
		let mut message = [0u8; 32];

		about.copy_from_slice(&bytes[..20]);
		domain.copy_from_slice(&bytes[20..40]);
		message.copy_from_slice(&bytes[41..]);

		let value = bytes[40];

		Ok(Self { about, domain, value, message })
	}

	/// Converts the struct into a vector of bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(73);

		bytes.extend(self.about);
		bytes.extend(self.domain);
		bytes.push(self.value);
		bytes.extend(self.message);

		bytes
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

impl TryFrom<AttestationCreatedFilter> for AttestationRaw {
	type Error = EigenError;

	fn try_from(log: AttestationCreatedFilter) -> Result<Self, Self::Error> {
		let about = log.about.to_fixed_bytes();

		let mut domain: [u8; 20] = [0; 20];
		domain.copy_from_slice(&log.key[DOMAIN_PREFIX_LEN..32]);

		let (value, message): (u8, [u8; 32]) = match log.val.len() {
			66 => (log.val[65], [0; 32]),
			98 => {
				let mut message = [0; 32];
				message.copy_from_slice(&log.val[66..]);
				(log.val[65], message)
			},
			_ => {
				return Err(EigenError::ValidationError(
					"Invalid attestation".to_string(),
				))
			},
		};

		Ok(AttestationRaw { about, domain, value, message })
	}
}

/// Attestation raw data payload.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SignatureRaw {
	/// The 'r' value of the ECDSA signature.
	pub(crate) sig_r: [u8; 32],
	/// The 's' value of the ECDSA signature.
	pub(crate) sig_s: [u8; 32],
	/// Recovery id of the ECDSA signature.
	pub(crate) rec_id: u8,
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

	/// Converts a vector of bytes into the struct.
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EigenError> {
		if bytes.len() != 65 {
			return Err(EigenError::ConversionError(
				"Input bytes vector should be of length 65".to_string(),
			));
		}

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];

		sig_r.copy_from_slice(&bytes[..32]);
		sig_s.copy_from_slice(&bytes[32..64]);
		let rec_id = bytes[64];

		Ok(Self { sig_r, sig_s, rec_id })
	}

	/// Converts the struct into a vector of bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(65);

		bytes.extend(self.sig_r);
		bytes.extend(self.sig_s);
		bytes.push(self.rec_id);

		bytes
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

impl TryFrom<AttestationCreatedFilter> for SignatureRaw {
	type Error = EigenError;

	fn try_from(log: AttestationCreatedFilter) -> Result<Self, Self::Error> {
		let len = log.val.len();
		if len != 66 && len != 98 {
			return Err(EigenError::ValidationError(
				"Invalid length: expected 66 or 98, got".to_string(),
			));
		}

		let sig_r: [u8; 32] = log.val[..32].try_into().map_err(|_| {
			EigenError::ValidationError("'sig_r' conversion to 32-byte array failed".to_string())
		})?;
		let sig_s: [u8; 32] = log.val[32..64].try_into().map_err(|_| {
			EigenError::ValidationError("'sig_s' conversion to 32-byte array failed".to_string())
		})?;

		let rec_id = log.val[64];

		Ok(SignatureRaw { sig_r, sig_s, rec_id })
	}
}

/// Attestation submission struct
#[derive(Clone, Debug, Default)]
pub struct SignedAttestationRaw {
	/// Attestation
	pub(crate) attestation: AttestationRaw,
	/// Signature
	pub(crate) signature: SignatureRaw,
}

impl SignedAttestationRaw {
	/// Constructor for signed attestations
	pub fn new(attestation: AttestationRaw, signature: SignatureRaw) -> Self {
		Self { attestation, signature }
	}

	/// Converts a vector of bytes into the struct.
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EigenError> {
		let attestation = AttestationRaw::from_bytes(bytes[..73].to_vec())?;
		let signature = SignatureRaw::from_bytes(bytes[73..].to_vec())?;

		Ok(Self { attestation, signature })
	}

	/// Converts the struct into a vector of bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(65 + 73);
		let attestation_bytes = self.attestation.to_bytes();
		let signature_bytes = self.signature.to_bytes();
		bytes.extend(attestation_bytes);
		bytes.extend(signature_bytes);

		bytes
	}
}

impl From<SignedAttestationEth> for SignedAttestationRaw {
	fn from(sign_att: SignedAttestationEth) -> Self {
		let attestation = AttestationRaw::from(sign_att.attestation);
		let signature = SignatureRaw::from(sign_att.signature);

		Self { attestation, signature }
	}
}

#[cfg(test)]
mod tests {
	use crate::att_station::AttestationData as ContractAttestationData;
	use crate::attestation::*;
	use ethers::{
		prelude::k256::ecdsa::SigningKey,
		signers::{Signer, Wallet},
		types::Bytes,
	};
	use secp256k1::{Message, Secp256k1, SecretKey};

	#[test]
	fn test_attestation_to_scalar_att() {
		// Build key
		let domain_input = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		// Message input
		let mut message = [
			0xff, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
			0x65, 0x6e, 0x79, 0xff,
		];

		// Address Input
		let mut address = [
			0xff, 0x47, 0x73, 0x4b, 0x6b, 0x42, 0x6e, 0x59, 0x61, 0x4c, 0x71, 0x4a, 0x45, 0x76,
			0x79, 0x4c, 0x6a, 0x73, 0x46, 0xff,
		];

		let attestation = AttestationEth::new(
			Address::from(address),
			H160::from(domain_input),
			Uint8::from(10),
			Some(H256::from(message)),
		);

		let attestation_fr = attestation.to_attestation_fr().unwrap();

		// Expected about
		let mut expected_about_input = [0u8; 32];
		address.reverse();
		expected_about_input[..20].copy_from_slice(&address);
		let expected_about = Scalar::from_bytes(&expected_about_input).unwrap();

		// Expected domain
		let mut expected_domain_input = [0u8; 32];
		expected_domain_input[DOMAIN_PREFIX_LEN..].copy_from_slice(&domain_input);
		expected_domain_input.reverse();
		let expected_domain = Scalar::from_bytes(&expected_domain_input).unwrap();

		// Expected value
		let expected_value = Scalar::from(10u64);

		// Expected message
		let mut expected_message_input = [0u8; 64];
		message.reverse();

		expected_message_input[..32].copy_from_slice(&message);
		let expected_message = Scalar::from_uniform_bytes(&expected_message_input);

		assert_eq!(attestation_fr.about, expected_about);
		assert_eq!(attestation_fr.domain, expected_domain);
		assert_eq!(attestation_fr.value, expected_value);
		assert_eq!(attestation_fr.message, expected_message);
	}

	#[test]
	fn test_attestation_payload_from_signed_att() {
		let secp = Secp256k1::new();
		let secret_key_as_bytes = [0x40; 32];
		let secret_key = SecretKey::from_slice(&secret_key_as_bytes).unwrap();

		let attestation_eth = AttestationEth::default();
		let attestation_raw: AttestationRaw = attestation_eth.clone().into();

		let attestation_fr = attestation_eth.to_attestation_fr().unwrap();

		let message = attestation_fr.hash().to_bytes();

		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);
		let sig_raw = SignatureRaw::from(signature);
		let sig_eth: SignatureEth = sig_raw.clone().into();

		let signed_attestation = SignedAttestationEth::new(attestation_eth, sig_eth);

		// Convert the signed attestation to attestation payload
		let attestation_payload = signed_attestation.to_payload();

		// Check the attestation payload
		let (recid, sig) = sig_raw.get_signature().serialize_compact();
		let mut payload_bytes = sig.to_vec();
		payload_bytes.push(recid.to_i32() as u8);
		payload_bytes.push(attestation_raw.value);

		assert_eq!(attestation_payload.to_vec(), payload_bytes);
	}

	#[test]
	fn test_address_from_signed_att() {
		let secp = Secp256k1::new();

		let secret_key_as_bytes = [0xcd; 32];

		let secret_key =
			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");

		let attestation_eth = AttestationEth::default();
		let attestation_fr = attestation_eth.to_attestation_fr().unwrap();
		let message = attestation_fr.hash().to_bytes();

		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);

		let signature_raw = SignatureRaw::from(signature);
		let signature_eth: SignatureEth = signature_raw.into();
		let signed_attestation = SignedAttestationEth::new(attestation_eth, signature_eth);

		// Replace with expected address
		let expected_address =
			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref()).unwrap()).address();

		let public_key = signed_attestation.recover_public_key().unwrap();
		let address = address_from_public_key(&public_key);

		assert_eq!(address, expected_address);
	}

	#[test]
	fn test_contract_att_data_from_signed_att() {
		let secp = Secp256k1::new();
		let secret_key_as_bytes = [0x40; 32];
		let secret_key =
			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");
		let about_bytes = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];
		// Build key
		let domain_input = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		// Message input
		let message = [
			0xff, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
			0x65, 0x6e, 0x79, 0xff,
		];

		let attestation_eth = AttestationEth::new(
			Address::from(about_bytes),
			H160::from(domain_input),
			Uint8::from(10),
			Some(H256::from(message)),
		);

		let attestation_fr = attestation_eth.to_attestation_fr().unwrap();

		let message = attestation_fr.hash().to_bytes();
		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);
		let signature_raw = SignatureRaw::from(signature);
		let signature_eth: SignatureEth = signature_raw.into();

		let signed_attestation = SignedAttestationEth::new(attestation_eth.clone(), signature_eth);

		let (_, about, key, payload) = signed_attestation.to_tx_data().unwrap();
		let contract_att_data = ContractAttestationData(about, key.to_fixed_bytes(), payload);

		let expected_address = Address::from(about_bytes);
		assert_eq!(contract_att_data.0, expected_address);

		let expected_key = attestation_eth.get_key();

		assert_eq!(contract_att_data.1, *expected_key.as_fixed_bytes());

		let expected_payload: Bytes = signed_attestation.to_payload();
		assert_eq!(contract_att_data.2, expected_payload);
	}
}
