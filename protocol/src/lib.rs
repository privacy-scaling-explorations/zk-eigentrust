//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge
//! features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity
//! are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good
//! behavior through several transactions. This is enforced for all users, so no
//! one can cheat the system and obtain a higher reputation. It is also
//! resistant to malicious collectives.
//!
//! ## Implementation
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.

#![feature(array_zip, array_try_map)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible, nonstandard_style, missing_docs, deprecated, unreachable_code,
	unreachable_patterns, absolute_paths_not_starting_with_crate, unsafe_code, clippy::panic,
	clippy::unnecessary_cast, clippy::cast_lossless, clippy::cast_possible_wrap
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// The module for defining the request-response protocol.
mod behaviour;
/// The module for global constants.
pub mod constants;
/// The module for epoch-related calculations, like seconds until the next
/// epoch, current epoch, etc.
mod epoch;
/// The module for the node setup, running the main loop, and handling network
/// events.
mod node;
/// The module for the peer related functionalities, like:
/// - Adding/removing neighbors
/// - Calculating the global trust score
/// - Calculating local scores toward neighbors for a given epoch
/// - Keeping track of neighbors scores towards us
mod peer;
/// Common utility functions used across the crate
mod utils;

pub use eigen_trust_circuit;
pub use epoch::Epoch;
pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
pub use log::LevelFilter;
pub use node::Node;
pub use peer::Peer;
pub use utils::{extract_pub_key, extract_sk_bytes, extract_sk_limbs, keypair_from_sk_bytes};

/// The crate-wide error variants.
#[derive(Debug, Clone, PartialEq)]
pub enum EigenError {
	/// Invalid keypair passed into node config.
	InvalidKeypair,
	/// Invalid multiaddress passed into node config.
	InvalidAddress,
	/// Invalid Pubkey
	InvalidPubkey,
	/// Invalid peer id passed.
	InvalidPeerId,
	/// Invalid trust score passed into node config.
	InvalidNumNeighbours,
	/// Peer not Identified
	PeerNotIdentified,
	/// Node failed to start listening on specified address. Usually because the
	/// address is already in use.
	ListenFailed,
	/// Node failed to connect to a neighbor.
	DialError,
	/// Max number of neighbors reached for a peer.
	MaxNeighboursReached,
	/// Failed to calculate current epoch.
	EpochError,
	/// Signature generation failed.
	SignatureError,
	/// Hash error
	HashError,
	/// Proving error
	ProvingError,
	/// Verification error
	VerificationError,
	/// Failed to generate proving key.
	KeygenFailed,
	/// Invalid bootstrap public key.
	InvalidBootstrapPubkey,
	/// Ivp not found
	IvpNotFound,
	/// Public key not found
	PubkeyNotFound,
	/// Neighbour not found,
	NeighbourNotFound,
	/// Invalid opinon
	InvalidIvp,
	/// Unknown error.
	Unknown,
}

impl From<EigenError> for u8 {
	fn from(e: EigenError) -> u8 {
		match e {
			EigenError::InvalidKeypair => 0,
			EigenError::InvalidAddress => 1,
			EigenError::InvalidPubkey => 2,
			EigenError::InvalidPeerId => 3,
			EigenError::InvalidNumNeighbours => 4,
			EigenError::PeerNotIdentified => 5,
			EigenError::ListenFailed => 6,
			EigenError::DialError => 7,
			EigenError::MaxNeighboursReached => 8,
			EigenError::EpochError => 9,
			EigenError::SignatureError => 10,
			EigenError::HashError => 11,
			EigenError::ProvingError => 12,
			EigenError::VerificationError => 13,
			EigenError::KeygenFailed => 14,
			EigenError::InvalidBootstrapPubkey => 15,
			EigenError::IvpNotFound => 16,
			EigenError::PubkeyNotFound => 17,
			EigenError::NeighbourNotFound => 18,
			EigenError::InvalidIvp => 19,
			EigenError::Unknown => 255,
		}
	}
}

impl From<u8> for EigenError {
	fn from(err: u8) -> Self {
		match err {
			0 => EigenError::InvalidKeypair,
			1 => EigenError::InvalidAddress,
			2 => EigenError::InvalidPubkey,
			3 => EigenError::InvalidPeerId,
			4 => EigenError::InvalidNumNeighbours,
			5 => EigenError::PeerNotIdentified,
			6 => EigenError::ListenFailed,
			7 => EigenError::DialError,
			8 => EigenError::MaxNeighboursReached,
			9 => EigenError::EpochError,
			10 => EigenError::SignatureError,
			11 => EigenError::HashError,
			12 => EigenError::ProvingError,
			13 => EigenError::VerificationError,
			14 => EigenError::KeygenFailed,
			15 => EigenError::InvalidBootstrapPubkey,
			16 => EigenError::IvpNotFound,
			17 => EigenError::PubkeyNotFound,
			18 => EigenError::NeighbourNotFound,
			19 => EigenError::InvalidIvp,
			_ => EigenError::Unknown,
		}
	}
}
