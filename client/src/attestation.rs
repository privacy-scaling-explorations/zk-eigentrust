use crate::att_station::AttestationData as ContractAttestationData;
use eigen_trust_circuit::{
	dynamic_sets::native::{AttestationFr, SignedAttestation},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use ethers::{
	types::{Address, Bytes, U256},
	utils::keccak256,
};
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
		Self { about, key, value, message: message.unwrap_or_else(|| U256::default()) }
	}

	pub fn to_attestation_fr(&self) -> AttestationFr {
		let about_bytes = self.about.as_bytes();
		let mut about_bytes_array = [0u8; 32];
		about_bytes_array[..about_bytes.len()].copy_from_slice(about_bytes);

		let key_bytes: &mut [u8] = &mut [];
		self.key.to_big_endian(key_bytes);
		let mut key_bytes_array = [0u8; 32];
		key_bytes_array[..key_bytes.len()].copy_from_slice(key_bytes);

		let message_bytes: &mut [u8] = &mut [];
		self.message.to_big_endian(message_bytes);
		let mut message_bytes_array = [0u8; 32];
		message_bytes_array[..message_bytes.len()].copy_from_slice(message_bytes);

		AttestationFr {
			about: Scalar::from_bytes(&about_bytes_array).unwrap(),
			key: Scalar::from_bytes(&key_bytes_array).unwrap(),
			value: Scalar::from(self.value as u64),
			message: Scalar::from_bytes(&message_bytes_array).unwrap(),
		}
	}
}

/// Attestation raw data payload
#[derive(Debug)]
pub struct AttestationPayload {
	sig_r: [u8; 32],
	sig_s: [u8; 32],
	rec_id: u8,
	value: u8,
	message: [u8; 32],
}

impl AttestationPayload {
	/// Convert a vector of bytes into the struct
	pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, &'static str> {
		if bytes.len() != 98 {
			return Err("Input bytes vector should be of length 98");
		}

		let mut sig_r = [0u8; 32];
		let mut sig_s = [0u8; 32];
		let mut message = [0u8; 32];

		let sig_r_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		sig_r.copy_from_slice(&sig_r_bytes);

		let sig_s_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		sig_s.copy_from_slice(&sig_s_bytes);

		let rec_id = bytes.remove(0);

		let value = bytes.remove(0);

		let message_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		message.copy_from_slice(&message_bytes);

		Ok(Self { sig_r, sig_s, rec_id, value, message })
	}

	/// Convert the struct into a vector of bytes
	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::new();

		bytes.extend_from_slice(&self.sig_r);
		bytes.extend_from_slice(&self.sig_s);
		bytes.push(self.value);
		bytes.push(self.rec_id);
		bytes.extend_from_slice(&self.message);

		bytes
	}

	/// Create AttestationPayload from SignedAttestation
	pub fn from_signed_attestation(
		signed_attestation: SignedAttestation,
	) -> Result<Self, &'static str> {
		todo!()
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

pub fn recover_ethereum_address(
	signed_attestation: &SignedAttestation,
) -> Result<ethers::core::types::Address, &'static str> {
	let public_key = signed_attestation.recover_public_key()?;
	let public_key_bytes = public_key.serialize_uncompressed();
	let hashed_public_key = keccak256(&public_key_bytes[1..]);
	let address_bytes = &hashed_public_key[hashed_public_key.len() - 20..];
	let address = ethers::core::types::Address::from_slice(address_bytes);

	Ok(address)
}

pub fn get_contract_attestation_data(
	signed_attestation: &SignedAttestation,
) -> Result<ContractAttestationData, &'static str> {
	// Recover the Ethereum address from the signed attestation
	let address = recover_ethereum_address(signed_attestation)?;

	// Calculate the hash of the attestation
	let attestation_hash = signed_attestation.attestation.hash().to_bytes();

	// Get the signature bytes
	let signature = signed_attestation.signature.serialize_compact().1;

	Ok(ContractAttestationData(
		address,
		attestation_hash,
		Bytes::from(signature.to_vec()),
	))
}

#[cfg(test)]
mod tests {
	// use crate::attestation::*;

	// #[test]
	// fn test_signed_attestation_to_contract_attestation_data() {
	// 	let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));
	// 	let attester = Address::random();
	// 	let signature = Signature::default();

	// 	let signed_attestation =
	// 		SignedAttestation::new(attestation.clone(), attester, signature.clone());

	// 	let contract_attestation_data: ContractAttestationData = signed_attestation.clone().into();

	// 	assert_eq!(contract_attestation_data.0, attestation.about);
	// 	assert_eq!(contract_attestation_data.1, attestation.key);

	// 	let payload = AttestationPayload::from(&signed_attestation);
	// 	let payload_bytes = payload.to_bytes();

	// 	assert_eq!(Bytes::from(payload_bytes), contract_attestation_data.2);
	// }

	// #[test]
	// fn test_attestation_to_scalar() {
	// 	let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));

	// 	let scalar_from_attestation: Scalar = (&attestation).into();

	// 	let about_bytes = attestation.about.as_bytes();
	// 	let mut about_bytes_array = [0u8; 32];
	// 	about_bytes_array[..about_bytes.len()].copy_from_slice(about_bytes);

	// 	let hash_input = [
	// 		Scalar::from_bytes(&about_bytes_array).unwrap(),
	// 		Scalar::from_bytes(&attestation.key).unwrap(),
	// 		Scalar::from(attestation.value as u64),
	// 		Scalar::from_bytes(&attestation.message).unwrap(),
	// 		Scalar::zero(),
	// 	];

	// 	let expected_scalar = PoseidonNativeHasher::new(hash_input).permute()[0];

	// 	assert_eq!(scalar_from_attestation, expected_scalar);
	// }

	// #[test]
	// fn test_attestation_payload_to_signed_attestation() {
	// 	let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));
	// 	let attester = Address::random();
	// 	let signature = Signature::default();

	// 	let signed_attestation =
	// 		SignedAttestation::new(attestation.clone(), attester, signature.clone());

	// 	let attestation_payload = AttestationPayload::from(&signed_attestation);

	// 	let reconstructed_signature = attestation_payload.get_signature();
	// 	let value = attestation_payload.get_value();
	// 	let message = attestation_payload.get_message();

	// 	assert_eq!(reconstructed_signature, signature);
	// 	assert_eq!(value, attestation.value);
	// 	assert_eq!(message, attestation.message);
	// }

	// #[test]
	// fn test_attestation_payload_bytes_to_struct_and_back() {
	// 	let sig_r_x = [0u8; 32];
	// 	let sig_r_y = [0u8; 32];
	// 	let sig_s = [0u8; 32];
	// 	let value = 5;
	// 	let message = [0u8; 32];

	// 	let mut input_bytes = Vec::new();
	// 	input_bytes.extend_from_slice(&sig_r_x);
	// 	input_bytes.extend_from_slice(&sig_r_y);
	// 	input_bytes.extend_from_slice(&sig_s);
	// 	input_bytes.push(value);
	// 	input_bytes.extend_from_slice(&message);

	// 	let attestation_payload =
	// 		AttestationPayload::from_bytes(input_bytes.clone()).expect("Valid input bytes");

	// 	assert_eq!(attestation_payload.sig_r_x, sig_r_x);
	// 	assert_eq!(attestation_payload.sig_r_y, sig_r_y);
	// 	assert_eq!(attestation_payload.sig_s, sig_s);
	// 	assert_eq!(attestation_payload.value, value);
	// 	assert_eq!(attestation_payload.message, message);

	// 	let output_bytes = attestation_payload.to_bytes();
	// 	assert_eq!(input_bytes, output_bytes);
	// }

	// #[test]
	// fn test_attestation_payload_from_bytes_error_handling() {
	// 	let invalid_payload_bytes = vec![0u8; 128]; // Incorrect length
	// 	let result = AttestationPayload::from_bytes(invalid_payload_bytes);

	// 	assert!(result.is_err());
	// 	assert_eq!(
	// 		result.unwrap_err(),
	// 		"Input bytes vector should be of length 129"
	// 	);
	// }
}
