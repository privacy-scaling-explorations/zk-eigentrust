use super::utils::extract_pub_key;
use crate::EigenError;
use eigen_trust_circuit::halo2wrong::curves::bn256::Fr as Bn256Scalar;
use libp2p::core::identity::Keypair as IdentityKeypair;

struct Pubkey(Bn256Scalar);

impl Pubkey {
	pub fn from_keypair(keypair: &IdentityKeypair) -> Result<Self, EigenError> {
		let pubkey = extract_pub_key(keypair)?;
		Ok(Self(pubkey))
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, EigenError> {
		let pubkey_opt: Option<Bn256Scalar> = Bn256Scalar::from_bytes(&bytes).into();
		let pubkey = pubkey_opt.ok_or_else(|| EigenError::InvalidPubkey)?;
		Ok(Self(pubkey))
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.0.to_bytes()
	}
}
