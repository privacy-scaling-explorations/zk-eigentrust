use crate::att_station::AttestationData as ContractAttestationData;
use eigen_trust_circuit::{eddsa::native::Signature, halo2::halo2curves::bn256::Fr as Scalar};
use ethers::types::{Address, Bytes};

#[derive(Clone)]
/// Attestation submission struct
pub struct SignedAttestation {
	/// Attestation
	pub attestation: Attestation,
	/// Attester Address
	pub attester: Address,
	/// Signature
	pub signature: Signature,
}

impl SignedAttestation {
	pub fn new(attestation: Attestation, attester: Address, signature: Signature) -> Self {
		Self { attestation, attester, signature }
	}
}

/// Conversion from `AttestationSubmission` to `att_station::AttestationData`.
impl From<SignedAttestation> for ContractAttestationData {
	fn from(submission: SignedAttestation) -> Self {
		Self {
			0: submission.attestation.about,
			1: submission.attestation.key,
			2: Bytes::from(AttestationPayload::from(&submission).to_bytes()),
		}
	}
}

#[derive(Clone)]
/// Attestation struct
pub struct Attestation {
	/// Ethereum address of peer being rated
	pub about: Address,
	/// Unique identifier for the action being rated
	pub key: [u8; 32],
	/// Given rating for the action
	pub value: u8,
	/// Optional field for attaching additional information to the attestation
	pub message: [u8; 32],
}

impl Attestation {
	/// Construct a new attestation struct
	pub fn new(about: Address, key: [u8; 32], value: u8, message: Option<[u8; 32]>) -> Self {
		Self { about, key, value, message: message.unwrap_or([0; 32]) }
	}
}

#[derive(Debug)]
/// Attestation raw data
pub struct AttestationPayload {
	sig_r_x: [u8; 32],
	sig_r_y: [u8; 32],
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

/// Conversion from `AttestationSubmission` to `AttestationPayload`
impl From<&SignedAttestation> for AttestationPayload {
	fn from(submission: &SignedAttestation) -> Self {
		Self {
			sig_r_x: submission.signature.big_r.x.to_bytes(),
			sig_r_y: submission.signature.big_r.y.to_bytes(),
			sig_s: submission.signature.s.to_bytes(),
			value: submission.attestation.value.clone(),
			message: submission.attestation.message.clone(),
		}
	}
}

#[cfg(test)]
mod tests {}
