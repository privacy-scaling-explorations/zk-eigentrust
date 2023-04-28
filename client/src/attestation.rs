use crate::att_station::AttestationData as ContractAttestationData;
use eigen_trust_circuit::{
	calculate_message_hash,
	eddsa::native::{sign, PublicKey, SecretKey},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use ethers::types::{Address, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
/// Attestation submission struct
pub struct AttestationSubmission {
	/// Attestation
	pub attestation: Attestation,
	/// Attester EDDSA secret key
	pub attester_sk: SecretKey,
	/// Attested EDDSA public key
	pub attested_pub_key: PublicKey,
}

impl AttestationSubmission {
	pub fn new(
		attestation: Attestation, attester_sk: SecretKey, attested_pub_key: PublicKey,
	) -> Self {
		Self { attestation, attester_sk, attested_pub_key }
	}
}

impl From<AttestationSubmission> for ContractAttestationData {
	fn from(submission: AttestationSubmission) -> Self {
		// Get the pks_hash
		// TODO: Implement message hash function for single neighbour attestations
		let (pks_hash, _) = calculate_message_hash::<1, 1>(
			vec![submission.attested_pub_key],
			vec![vec![Scalar::from(submission.attestation.value as u64)]],
		);

		let payload = AttestationPayload::from(submission.clone());

		Self(
			submission.attestation.about,
			pks_hash.to_bytes(), // TODO: check this value
			Bytes::from(payload.to_bytes()),
		)
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
	pub fn new(about: Address, key: u32, value: u8, message: Option<[u8; 32]>) -> Self {
		Self { about, key, value, message: message.unwrap_or([0; 32]) }
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Attestation raw data
pub struct AttestationPayload {
	sig_r_x: [u8; 32],
	sig_r_y: [u8; 32],
	sig_s: [u8; 32],
	value: u8,
	message: [u8; 32],
}

impl AttestationPayload {
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

impl From<AttestationSubmission> for AttestationPayload {
	fn from(submission: AttestationSubmission) -> Self {
		let value = submission.attestation.value;
		let message = submission.attestation.message;

		// Get the message hash
		// TODO: Implement message hash function for single neighbour attestations
		let (_, message_hash) = calculate_message_hash::<1, 1>(
			vec![submission.attested_pub_key],
			vec![vec![Scalar::from(submission.attestation.value as u64)]],
		);

		let signature = sign(
			&submission.attester_sk,
			&submission.attester_sk.public(),
			message_hash[0],
		);

		let sig_r_x = signature.big_r.x.to_bytes();
		let sig_r_y = signature.big_r.y.to_bytes();
		let sig_s = signature.s.to_bytes();

		Self { sig_r_x, sig_r_y, sig_s, value, message }
	}
}

#[cfg(test)]
mod tests {}
