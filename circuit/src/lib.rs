//! The module for the main EigenTrust circuit.

#![feature(slice_flatten)]
#![feature(array_zip, array_try_map)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible, nonstandard_style, missing_docs, deprecated, unreachable_code,
	unreachable_patterns, absolute_paths_not_starting_with_crate, unsafe_code, clippy::panic,
	clippy::unnecessary_cast, clippy::cast_lossless, clippy::cast_possible_wrap
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// Closed graph circuit
pub mod circuit;
/// Ecc arithemtic on wrong field
pub mod ecc;
/// EDDSA signature scheme gadgets + native version
pub mod eddsa;
/// Edwards curve operations
pub mod edwards;
/// Common gadgets used across circuits
pub mod gadgets;
/// Integer type - Wrong field arithmetic
pub mod integer;
/// A module for defining round parameters and MDS matrix for hash
/// permutations
pub mod params;
/// Poseidon hash function gadgets + native version
pub mod poseidon;
/// Rescue Prime hash function gadgets + native version
pub mod rescue_prime;
/// Utilities for proving and verifying
pub mod utils;

pub use halo2wrong;
