use crate::{
	att_station::AttestationData as ContractAttestationData, eth::address_from_public_key,
};
use eigen_trust_circuit::{
	dynamic_sets::native::{AttestationFr, SignedAttestation},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use ethers::types::{Address, U256};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

/// Attestation struct
#[derive(Clone, Debug)]
pub struct Attestation {
	/// Ethereum address of peer being rated
	pub about: Address,
	/// Unique identifier for the action being rated
	pub key: U256,
	/// Given rating for the action
	pub value: u8,
	/// Optional field for attaching additional information to the attestation
	pub message: U256,
}

impl Attestation {
	/// Construct a new attestation struct
	pub fn new(about: Address, key: U256, value: u8, message: Option<U256>) -> Self {
		Self { about, key, value, message: message.unwrap_or(U256::from(0)) }
	}

	pub fn to_attestation_fr(&self) -> AttestationFr {
		let about_bytes = self.about.as_bytes();
		let mut about_bytes_array = [0u8; 32];
		about_bytes_array[..about_bytes.len()].copy_from_slice(about_bytes);

		AttestationFr {
			about: Scalar::from_bytes(&about_bytes_array).unwrap(),
			key: Scalar::from(self.key.0[0]),
			value: Scalar::from(self.value as u64),
			message: Scalar::from(self.message.0[0]),
		}
	}
}

/// Attestation raw data payload
#[derive(Clone, Debug, PartialEq)]
pub struct AttestationPayload {
	sig_r: [u8; 32],
	sig_s: [u8; 32],
	rec_id: u8,
	value: u8,
	message: [u8; 32],
}

impl AttestationPayload {
	/// Convert a vector of bytes into the struct
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, &'static str> {
		if bytes.len() != 98 {
			return Err("Input bytes vector should be of length 98");
		}

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];
		let mut message = [0u8; 32];

		sig_r.copy_from_slice(&bytes[..32]);
		sig_s.copy_from_slice(&bytes[32..64]);
		let rec_id = bytes[64];
		let value = bytes[65];
		message.copy_from_slice(&bytes[66..98]);

		Ok(Self { sig_r, sig_s, rec_id, value, message })
	}

	/// Create AttestationPayload from SignedAttestation
	pub fn from_signed_attestation(
		signed_attestation: &SignedAttestation,
	) -> Result<Self, &'static str> {
		let (rec_id, signature) = signed_attestation.signature.serialize_compact();

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];

		sig_r.copy_from_slice(&signature[0..32]);
		sig_s.copy_from_slice(&signature[32..64]);

		let rec_id = rec_id.to_i32() as u8;

		let value = signed_attestation.attestation.value.to_bytes()[0];

		let message = signed_attestation.attestation.message.to_bytes();

		Ok(Self { sig_r, sig_s, rec_id, value, message })
	}

	/// Convert the struct into a vector of bytes
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(98);

		bytes.extend_from_slice(&self.sig_r);
		bytes.extend_from_slice(&self.sig_s);
		bytes.push(self.rec_id);
		bytes.push(self.value);
		bytes.extend_from_slice(&self.message);

		bytes
	}

	/// Get the ECDSA recoverable signature
	pub fn get_signature(&self) -> RecoverableSignature {
		let concat_sig = [self.sig_r, self.sig_s].concat();
		let recovery_id = RecoveryId::from_i32(self.rec_id as i32).unwrap();

		RecoverableSignature::from_compact(concat_sig.as_slice(), recovery_id).unwrap()
	}

	/// Get the value
	pub fn get_value(&self) -> u8 {
		self.value
	}

	/// Get the message
	pub fn get_message(&self) -> [u8; 32] {
		self.message
	}
}

/// Recover the signing Ethereum address from a signed attestation
pub fn address_from_signed_att(
	signed_attestation: &SignedAttestation,
) -> Result<Address, &'static str> {
	// Get the signing key
	let public_key = signed_attestation.recover_public_key()?;

	// Get the address from the public key
	address_from_public_key(&public_key)
}

/// Construct the contract attestation data from a signed attestation
pub fn att_data_from_signed_att(
	signed_attestation: &SignedAttestation,
) -> Result<ContractAttestationData, &'static str> {
	// Recover the Ethereum address from the signed attestation
	let address = address_from_signed_att(signed_attestation)?;

	// Calculate the hash of the attestation
	let attestation_hash = signed_attestation.attestation.hash().to_bytes();

	// Get the payload bytes
	let payload = AttestationPayload::from_signed_attestation(&signed_attestation)?;

	Ok(ContractAttestationData(
		address,
		attestation_hash,
		payload.to_bytes().into(),
	))
}

#[cfg(test)]
mod tests {
	use crate::attestation::*;
	use ethers::{
		prelude::k256::ecdsa::SigningKey,
		signers::{Signer, Wallet},
		types::Bytes,
	};
	use secp256k1::{ecdsa::RecoveryId, Message, Secp256k1, SecretKey};

	#[test]
	fn test_attestation_to_scalar_att() {
		let attestation = Attestation::new(
			Address::zero(),
			U256::from(140317563),
			10,
			Some(U256::from(140317564)),
		);

		let attestation_fr = attestation.to_attestation_fr();

		let expected_about = Scalar::from(0u64);
		let expected_key = Scalar::from(140317563u64);
		let expected_value = Scalar::from(10u64);
		let expected_message = Scalar::from(140317564u64);

		assert_eq!(attestation_fr.about, expected_about);
		assert_eq!(attestation_fr.key, expected_key);
		assert_eq!(attestation_fr.value, expected_value);
		assert_eq!(attestation_fr.message, expected_message);
	}

	#[test]
	fn test_attestation_payload_from_signed_att() {
		let secp = Secp256k1::new();
		let secret_key_as_bytes = [0x40; 32];
		let secret_key = SecretKey::from_slice(&secret_key_as_bytes).unwrap();

		let attestation = AttestationFr {
			about: Scalar::zero(),
			key: Scalar::zero(),
			value: Scalar::zero(),
			message: Scalar::zero(),
		};

		let message = attestation.hash().to_bytes();

		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);

		let signed_attestation = SignedAttestation { attestation, signature };

		// Convert the signed attestation to attestation payload
		let attestation_payload =
			AttestationPayload::from_signed_attestation(&signed_attestation).unwrap();

		// Check the attestation payload
		let (recid, sig) = signed_attestation.signature.serialize_compact();
		assert_eq!(attestation_payload.sig_r, sig[0..32]);
		assert_eq!(attestation_payload.sig_s, sig[32..64]);
		assert_eq!(attestation_payload.rec_id, recid.to_i32() as u8);
		assert_eq!(
			attestation_payload.value,
			signed_attestation.attestation.value.to_bytes()[0]
		);
		assert_eq!(
			attestation_payload.message,
			signed_attestation.attestation.message.to_bytes()
		);
	}

	#[test]
	fn test_attestation_payload_to_signed_att() {
		let secp = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
		let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

		let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);

		let (recovery_id, serialized_sig) = signature.serialize_compact();

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];
		sig_r.copy_from_slice(&serialized_sig[0..32]);
		sig_s.copy_from_slice(&serialized_sig[32..64]);

		let payload = AttestationPayload {
			sig_r,
			sig_s,
			rec_id: recovery_id.to_i32() as u8,
			value: 5,
			message: [3u8; 32],
		};

		let sig = payload.get_signature();

		assert_eq!(
			sig.serialize_compact().0,
			RecoveryId::from_i32(payload.rec_id as i32).unwrap()
		);
		assert_eq!(
			sig.serialize_compact().1.as_slice(),
			[payload.sig_r, payload.sig_s].concat().as_slice()
		);
	}

	#[test]
	fn test_attestation_payload_bytes_to_struct_and_back() {
		let payload = AttestationPayload {
			sig_r: [0u8; 32],
			sig_s: [0u8; 32],
			rec_id: 0,
			value: 10,
			message: [0u8; 32],
		};

		let bytes = payload.clone().to_bytes();

		let result_payload = AttestationPayload::from_bytes(bytes).unwrap();

		assert_eq!(payload, result_payload);
	}

	#[test]
	fn test_attestation_payload_from_bytes_error_handling() {
		let bytes = vec![0u8; 99];
		let result = AttestationPayload::from_bytes(bytes);
		assert!(result.is_err());
	}

	#[test]
	fn test_address_from_signed_att() {
		let secp = Secp256k1::new();

		let secret_key_as_bytes = [0xcd; 32];

		let secret_key =
			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");

		let attestation = AttestationFr {
			about: Scalar::zero(),
			key: Scalar::zero(),
			value: Scalar::zero(),
			message: Scalar::zero(),
		};

		let message = attestation.hash().to_bytes();

		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);

		let signed_attestation = SignedAttestation { attestation, signature };

		// Replace with expected address
		let expected_address =
			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref()).unwrap()).address();

		assert_eq!(
			address_from_signed_att(&signed_attestation).unwrap(),
			expected_address
		);
	}

	#[test]
	fn test_contract_att_data_from_signed_att() {
		let secp = Secp256k1::new();
		let secret_key_as_bytes = [0x40; 32];
		let secret_key =
			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");

		let attestation = Attestation::new(
			Address::zero(),
			U256::from(140317563),
			10,
			Some(U256::from(140317564)),
		);

		let message = attestation.to_attestation_fr().hash().to_bytes();

		let signature = secp.sign_ecdsa_recoverable(
			&Message::from_slice(message.as_slice()).unwrap(),
			&secret_key,
		);

		let signed_attestation =
			SignedAttestation { attestation: attestation.to_attestation_fr(), signature };

		let contract_att_data = att_data_from_signed_att(&signed_attestation).unwrap();

		let expected_address =
			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref()).unwrap()).address();
		assert_eq!(contract_att_data.0, expected_address);

		let expected_attestation_hash = signed_attestation.attestation.hash().to_bytes();
		assert_eq!(contract_att_data.1, expected_attestation_hash);

		let expected_payload: Bytes =
			AttestationPayload::from_signed_attestation(&signed_attestation)
				.unwrap()
				.to_bytes()
				.into();
		assert_eq!(contract_att_data.2, expected_payload);
	}
}
