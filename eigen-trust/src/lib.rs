#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible,
	nonstandard_style,
	deprecated,
	unreachable_code,
	unreachable_patterns,
	absolute_paths_not_starting_with_crate,
	unsafe_code,
	clippy::unwrap_used,
	clippy::panic,
	clippy::unnecessary_cast,
	clippy::cast_lossless,
	clippy::cast_possible_truncation,
	clippy::cast_possible_wrap,
	clippy::cast_precision_loss,
	clippy::cast_sign_loss
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

mod epoch;
mod node;
mod peer;
mod protocol;

pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
pub use log::LevelFilter;
pub use node::{Node, NodeConfig};
pub use peer::Peer;

#[derive(Debug)]
#[repr(u8)]
pub enum EigenError {
	InvalidKeypair,
	InvalidAddress,
	InvalidPeerId,
	InvalidEpoch,
	InvalidNumNeighbours,
	ListenFailed,
	DialError,
	ResponseError,
	MaxNeighboursReached,
	NeighbourNotFound,
	OpinionNotFound,
	GlobalScoreNotFound,
	EpochError,
	InvalidEpochBytes,
	InvalidOpinionBytes,
}
