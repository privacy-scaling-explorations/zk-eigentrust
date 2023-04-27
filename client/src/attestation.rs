use eigen_trust_circuit::eddsa::native::Signature;
use ethers::types::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Attestation raw data
pub struct AttestationData {
	sig_r_x: [u8; 32],
	sig_r_y: [u8; 32],
	sig_s: [u8; 32],
	value: u8,
	message: [u8; 32],
}

impl AttestationData {
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
}

impl From<Attestation> for AttestationData {
	fn from(att: Attestation) -> Self {
		// Hash the Attestation struct using the Poseidon hash function
		// let att_hash = Poseidon::hash(&att);

		// Sign the hash using the ECDSA algorithm with the provided keys
		// let sig = ECDSA::sign(&att_hash, &keys);

		Self {
			sig_r_x: [0; 32],
			sig_r_y: [0; 32],
			sig_s: [0; 32],
			value: att.value,
			message: att.message,
		}
	}
}

#[derive(Clone)]
/// Attestation struct
pub struct Attestation {
	/// Ethereum address of peer being rated
	pub about: Address,
	/// Unique identifier for the action being rated
	pub key: u32,
	/// Given rating for the action
	pub value: u8,
	/// Optional field for attaching additional information to the attestation
	pub message: [u8; 32],
}

impl Attestation {
	/// Construct a new attestation for given data
	pub fn new(about: Address, key: u32, value: u8, message: [u8; 32]) -> Self {
		Self { about, key, value, message }
	}

	pub fn hash_attestation(attestation: &Attestation) -> [u8; 32] {
		// TODO: Implement hash function
		[0u8; 32]
	}
}

impl From<AttestationData> for Attestation {
	fn from(att: AttestationData) -> Self {
		Self { about: Address::default(), key: 0u32, value: att.value, message: att.message }
	}
}

pub struct AttestationTransaction {
	/// Attestation
	pub attestation: Attestation,
	/// Signature
	pub signature: Signature,
}

#[cfg(test)]
mod tests {}
