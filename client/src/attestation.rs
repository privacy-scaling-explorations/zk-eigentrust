use crate::att_station::AttestationData as ContractAttestationData;
use eigen_trust_circuit::{
	dynamic_sets::native::{AttestationFr, SignedAttestation},
	eddsa::native::Signature,
	halo2::halo2curves::bn256::Fr as Scalar,
};
use revm_primitives::{Address, B256};

// impl ContractAttestationData {
// 	/// Conversion from `SignedAttestation` to `att_station::AttestationData`.
// 	fn new_from_signed_attestation(submission: SignedAttestation) -> Self {
// 		Self(
// 			submission.attestation.about,
// 			submission.attestation.key,
// 			Bytes::from(AttestationPayload::from(&submission).to_bytes()),
// 		)
// 	}
// }

/// Attestation struct
#[derive(Clone, Debug)]
pub struct Attestation {
	/// Ethereum address of peer being rated
	pub about: Address,
	/// Unique identifier for the action being rated
	pub key: B256,
	/// Given rating for the action
	pub value: u8,
	/// Optional field for attaching additional information to the attestation
	pub message: B256,
}

impl Attestation {
	/// Construct a new attestation struct
	pub fn new(about: Address, key: B256, value: u8, message: Option<B256>) -> Self {
		Self { about, key, value, message: message.unwrap_or_else(|| B256::default()) }
	}

	pub fn to_attestation_fr(&self) -> AttestationFr {
		let about_bytes = self.about.as_bytes();
		let mut about_bytes_array = [0u8; 32];
		about_bytes_array[..about_bytes.len()].copy_from_slice(about_bytes);

		AttestationFr {
			about: Scalar::from_bytes(&about_bytes_array).unwrap(),
			key: Scalar::from_bytes(&self.key).unwrap(),
			value: Scalar::from(self.value as u64),
			message: Scalar::from_bytes(&self.message).unwrap(),
		}
	}
}

/// Attestation raw data payload
#[derive(Debug)]
pub struct AttestationPayload {
	sig_r: [u8; 32],
	sig_s: [u8; 32],
	value: u8,
	message: [u8; 32],
}

impl AttestationPayload {
	/// Convert a vector of bytes into the struct
	pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, &'static str> {
		if bytes.len() != 129 {
			return Err("Input bytes vector should be of length 129");
		}

		let mut sig_r_x = [0u8; 32];
		let mut sig_r_y = [0u8; 32];
		let mut sig_s = [0u8; 32];
		let mut message = [0u8; 32];

		let sig_r_x_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		sig_r_x.copy_from_slice(&sig_r_x_bytes);

		let sig_r_y_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		sig_r_y.copy_from_slice(&sig_r_y_bytes);

		let sig_s_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		sig_s.copy_from_slice(&sig_s_bytes);

		let value = bytes.remove(0);

		let message_bytes = bytes.drain(0..32).collect::<Vec<u8>>();
		message.copy_from_slice(&message_bytes);

		Ok(Self { sig_r_x, sig_r_y, sig_s, value, message })
	}

	/// Convert the struct into a vector of bytes
	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::new();

		bytes.extend_from_slice(&self.sig_r_x);
		bytes.extend_from_slice(&self.sig_r_y);
		bytes.extend_from_slice(&self.sig_s);
		bytes.push(self.value);
		bytes.extend_from_slice(&self.message);

		bytes
	}

	pub fn from_signed_attestation(signed_attestation: &SignedAttestation) -> Self {
		Self {
			sig_r: signed_attestation.signature.big_r.x.to_bytes(),
			sig_s: signed_attestation.signature.big_r.y.to_bytes(),
			sig_v: signed_attestation.signature.s.to_bytes(),
			value: signed_attestation.attestation.value.into(),
			message: signed_attestation.attestation.message.into(),
		}
	}

	/// Get the EDDSA signature
	pub fn get_signature(&self) -> Signature {
		Signature::new(
			Scalar::from_bytes(&self.sig_r_x).unwrap(),
			Scalar::from_bytes(&self.sig_r_y).unwrap(),
			Scalar::from_bytes(&self.sig_s).unwrap(),
		)
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

#[cfg(test)]
mod tests {
	use crate::attestation::*;

	#[test]
	fn test_signed_attestation_to_contract_attestation_data() {
		let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));
		let attester = Address::random();
		let signature = Signature::default();

		let signed_attestation =
			SignedAttestation::new(attestation.clone(), attester, signature.clone());

		let contract_attestation_data: ContractAttestationData = signed_attestation.clone().into();

		assert_eq!(contract_attestation_data.0, attestation.about);
		assert_eq!(contract_attestation_data.1, attestation.key);

		let payload = AttestationPayload::from(&signed_attestation);
		let payload_bytes = payload.to_bytes();

		assert_eq!(Bytes::from(payload_bytes), contract_attestation_data.2);
	}

	#[test]
	fn test_attestation_to_scalar() {
		let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));

		let scalar_from_attestation: Scalar = (&attestation).into();

		let about_bytes = attestation.about.as_bytes();
		let mut about_bytes_array = [0u8; 32];
		about_bytes_array[..about_bytes.len()].copy_from_slice(about_bytes);

		let hash_input = [
			Scalar::from_bytes(&about_bytes_array).unwrap(),
			Scalar::from_bytes(&attestation.key).unwrap(),
			Scalar::from(attestation.value as u64),
			Scalar::from_bytes(&attestation.message).unwrap(),
			Scalar::zero(),
		];

		let expected_scalar = PoseidonNativeHasher::new(hash_input).permute()[0];

		assert_eq!(scalar_from_attestation, expected_scalar);
	}

	#[test]
	fn test_attestation_payload_to_signed_attestation() {
		let attestation = Attestation::new(Address::random(), [0u8; 32], 5, Some([0u8; 32]));
		let attester = Address::random();
		let signature = Signature::default();

		let signed_attestation =
			SignedAttestation::new(attestation.clone(), attester, signature.clone());

		let attestation_payload = AttestationPayload::from(&signed_attestation);

		let reconstructed_signature = attestation_payload.get_signature();
		let value = attestation_payload.get_value();
		let message = attestation_payload.get_message();

		assert_eq!(reconstructed_signature, signature);
		assert_eq!(value, attestation.value);
		assert_eq!(message, attestation.message);
	}

	#[test]
	fn test_attestation_payload_bytes_to_struct_and_back() {
		let sig_r_x = [0u8; 32];
		let sig_r_y = [0u8; 32];
		let sig_s = [0u8; 32];
		let value = 5;
		let message = [0u8; 32];

		let mut input_bytes = Vec::new();
		input_bytes.extend_from_slice(&sig_r_x);
		input_bytes.extend_from_slice(&sig_r_y);
		input_bytes.extend_from_slice(&sig_s);
		input_bytes.push(value);
		input_bytes.extend_from_slice(&message);

		let attestation_payload =
			AttestationPayload::from_bytes(input_bytes.clone()).expect("Valid input bytes");

		assert_eq!(attestation_payload.sig_r_x, sig_r_x);
		assert_eq!(attestation_payload.sig_r_y, sig_r_y);
		assert_eq!(attestation_payload.sig_s, sig_s);
		assert_eq!(attestation_payload.value, value);
		assert_eq!(attestation_payload.message, message);

		let output_bytes = attestation_payload.to_bytes();
		assert_eq!(input_bytes, output_bytes);
	}

	#[test]
	fn test_attestation_payload_from_bytes_error_handling() {
		let invalid_payload_bytes = vec![0u8; 128]; // Incorrect length
		let result = AttestationPayload::from_bytes(invalid_payload_bytes);

		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err(),
			"Input bytes vector should be of length 129"
		);
	}
}
