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
//! ## Usage (Milestone 1 Version)
//! ```rust
//! use eigen_trust::{
//! 	network::{Network, NetworkConfig},
//! 	peer::TransactionRating,
//! };
//! use rand::thread_rng;
//!
//! // Configure the network.
//! struct ExampleNetworkConfig;
//! impl NetworkConfig for ExampleNetworkConfig {
//! 	const DELTA: f64 = 0.0001;
//! 	const MAX_ITERATIONS: usize = 1000;
//! 	const NUM_MANAGERS: u64 = 2;
//! 	const PRETRUST_WEIGHT: f64 = 0.5;
//! 	const SIZE: usize = 16;
//! }
//!
//! let rng = &mut thread_rng();
//! let num_peers: usize = ExampleNetworkConfig::SIZE;
//!
//! let default_score = 1. / num_peers as f64;
//! let mut pre_trust_scores = vec![default_score; num_peers];
//!
//! let mut network = Network::<ExampleNetworkConfig>::bootstrap(pre_trust_scores).unwrap();
//!
//! network
//! 	.mock_transaction(0, 1, TransactionRating::Positive)
//! 	.unwrap();
//! network
//! 	.mock_transaction(1, 0, TransactionRating::Positive)
//! 	.unwrap();
//! network
//! 	.mock_transaction(2, 3, TransactionRating::Positive)
//! 	.unwrap();
//!
//! network.converge(rng);
//!
//! let global_trust_scores = network.get_global_trust_scores();
//!
//! println!("is_converged: {}", network.is_converged());
//! println!("{:?}", global_trust_scores);
//! ```
//! ## Implementation
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.
//!
//! NOTE: This library is still in development. Use at your own risk.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible,
	nonstandard_style,
	missing_docs,
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

/// The module for the higher-level network functions.
/// It contains the functionality for creating peers, bootstrapping the
/// networks, and interactions between peers.
pub mod network;

/// The module for peer management. It contains the functionality for creating a
/// peer, adding local trust scores, and calculating the global trust score.
pub mod manager;

/// The module for basic peer functions. It contains the functionality for
/// transacting with other peers, and calulating local trust scores.
pub mod peer;

/// The module for kd tree structure. Used for 2d space partitioning.
pub mod kd_tree;

/// The module wide error variants.
#[derive(Debug, PartialEq, Eq)]
pub enum EigenError {
	/// Invalid pre trust scores passed
	InvalidPreTrustScores,
	/// Peer not found in the network or peer cache
	PeerNotFound,
	/// Managers couldn't agree on the global trust score for a peer
	GlobalTrustCalculationFailed,
	/// Invalid keys for the manager generated
	InvalidManagerKeys,
}
