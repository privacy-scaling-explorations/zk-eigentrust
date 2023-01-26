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
	future_incompatible, nonstandard_style, deprecated, unreachable_code, unreachable_patterns,
	absolute_paths_not_starting_with_crate, unsafe_code, clippy::panic, clippy::unnecessary_cast,
	clippy::cast_lossless, clippy::cast_possible_wrap, missing_docs
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// The module for epoch-related calculations, like seconds until the next
/// epoch, current epoch, etc.
pub mod epoch;
/// The module where the error enum is defined
pub mod error;
/// Helper functions and ABIs for ethereum
pub mod ethereum;
/// The module for the manager related functionalities, like:
/// - Adding/removing neighbors of peers
/// - Calculating the score of peers
/// - Keeping track of neighbors scores towards us
pub mod manager;
/// Common utility functions used across the crate
pub mod utils;
