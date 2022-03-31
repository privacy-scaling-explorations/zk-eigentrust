//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good behavior through several transactions.
//! This is enforced for all users, so no one can cheat the system and obtain a higher reputation.
//! It is also resistant to malicious collectives.
//!
//! ## Implementation
//! The library is implemented accourding to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.
//!
//! NOTE: This library is still in development. Use at your own risk.

/// The module for the higher level network functions. It contains the functionality for creating peers,
/// bootstrapping the networks, and interactions between peers.
pub mod network;

/// The module for peer management. It contains the functionality for creating a peer,
/// adding local trust scores and calculating the global global trust score.
pub mod peer;

/// The module for utility functions.
pub mod utils;
