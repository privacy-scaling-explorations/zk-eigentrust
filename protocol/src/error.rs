use serde::ser::StdError;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The crate-wide error variants.
#[derive(Debug, Clone, PartialEq)]
pub enum EigenError {
	/// Invalid pubkey of the bootstrap peer
	InvalidBootstrapPubkey,
	/// Error while making proof
	ProvingError,
	/// Error while verifying the proof
	VerificationError,
	/// Client connection error
	ConnectionError,
	/// Failed to listen to requests
	ListenError,
	/// Signature not found
	SignatureNotFound,
	/// Unknown error.
	Unknown,
}

impl From<EigenError> for u8 {
	fn from(e: EigenError) -> u8 {
		match e {
			EigenError::InvalidBootstrapPubkey => 0,
			EigenError::ProvingError => 1,
			EigenError::VerificationError => 2,
			EigenError::ConnectionError => 3,
			EigenError::ListenError => 4,
			EigenError::SignatureNotFound => 5,
			EigenError::Unknown => 255,
		}
	}
}

impl From<u8> for EigenError {
	fn from(err: u8) -> Self {
		match err {
			0 => EigenError::InvalidBootstrapPubkey,
			1 => EigenError::ProvingError,
			2 => EigenError::VerificationError,
			3 => EigenError::ConnectionError,
			4 => EigenError::ListenError,
			5 => EigenError::SignatureNotFound,
			_ => EigenError::Unknown,
		}
	}
}

impl Display for EigenError {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		write!(f, "{:?}", self)?;
		Ok(())
	}
}

impl StdError for EigenError {}
