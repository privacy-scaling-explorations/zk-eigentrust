//! # Error Module.
//!
//! This module features the `EigenError` enum for error handling throughout the project.

use thiserror::Error;

/// The crate-wide error variants.
#[derive(Debug, Error)]
pub enum EigenError {
	/// Attestation error
	#[error("AttestationError: {0}")]
	AttestationError(String),

	/// Configuration error
	#[error("ConfigurationError: {0}")]
	ConfigurationError(String),

	/// Connection error
	#[error("ConnectionError: {0}")]
	ConnectionError(String),

	/// Contract compilation error
	#[error("ContractCompilationError: {0}")]
	ContractCompilationError(String),

	/// File read/write error
	#[error("FileIOError: {0}")]
	FileIOError(String),

	/// Input/output error
	#[error("IOError: {0}")]
	IOError(std::io::Error),

	/// Network error
	#[error("NetworkError: {0}")]
	NetworkError(String),

	/// Parsing error
	#[error("ParsingError: {0}")]
	ParsingError(String),

	/// Recovery error
	#[error("RecoveryError: {0}")]
	RecoveryError(String),

	/// Resource unavailable error
	#[error("ResourceUnavailableError: {0}")]
	ResourceUnavailableError(String),

	/// Transaction error
	#[error("TransactionError: {0}")]
	TransactionError(String),

	/// Unknown error
	#[error("UnknownError: {0}")]
	UnknownError(String),

	/// Validation error
	#[error("ValidationError: {0}")]
	ValidationError(String),
}
