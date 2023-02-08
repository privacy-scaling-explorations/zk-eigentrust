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

use crate::circuit::{PoseidonNativeHasher, PoseidonNativeSponge};
use eddsa::native::PublicKey;
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::bn256::Fr as Scalar,
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
};

pub use halo2;

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
/// MerkleTree
pub mod merkle_tree;
/// A module for defining round parameters and MDS matrix for hash
/// permutations
pub mod params;
/// Poseidon hash function gadgets + native version
pub mod poseidon;
/// Rescue Prime hash function gadgets + native version
pub mod rescue_prime;
/// Utilities for proving and verifying
pub mod utils;
/// PLONK verifier
pub mod verifier;

#[derive(Debug)]
/// Region Context struct for managing region assignments
pub struct RegionCtx<'a, F: FieldExt> {
	/// Region struct
	region: Region<'a, F>,
	/// Current row offset
	offset: usize,
}

impl<'a, F: FieldExt> RegionCtx<'a, F> {
	/// Construct new Region Context
	pub fn new(region: Region<'a, F>, offset: usize) -> RegionCtx<'a, F> {
		RegionCtx { region, offset }
	}

	/// Return current row offset
	pub fn offset(&self) -> usize {
		self.offset
	}

	/// Turn into region struct
	pub fn into_region(self) -> Region<'a, F> {
		self.region
	}

	/// Assign value to a fixed column
	pub fn assign_fixed(
		&mut self, column: Column<Fixed>, value: F,
	) -> Result<AssignedCell<F, F>, Error> {
		self.region.assign_fixed(
			|| format!("fixed_{}", self.offset),
			column,
			self.offset,
			|| Value::known(value),
		)
	}

	/// Assign to advice column from an instance column
	pub fn assign_from_instance(
		&mut self, advice: Column<Advice>, instance: Column<Instance>, index: usize,
	) -> Result<AssignedCell<F, F>, Error> {
		self.region.assign_advice_from_instance(
			|| format!("advice_{}", self.offset),
			instance,
			index,
			advice,
			self.offset,
		)
	}

	/// Assign to advice column from an instance column
	pub fn assign_from_constant(
		&mut self, advice: Column<Advice>, constant: F,
	) -> Result<AssignedCell<F, F>, Error> {
		self.region.assign_advice_from_constant(
			|| format!("advice_{}", self.offset),
			advice,
			self.offset,
			constant,
		)
	}

	/// Assign value to an advice column
	pub fn assign_advice(
		&mut self, column: Column<Advice>, value: Value<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		self.region.assign_advice(
			|| format!("advice_{}", self.offset),
			column,
			self.offset,
			|| value,
		)
	}

	/// Copy value from passed assigned cell into an advice column
	pub fn copy_assign(
		&mut self, column: Column<Advice>, value: AssignedCell<F, F>,
	) -> Result<AssignedCell<F, F>, Error> {
		value.copy_advice(
			|| format!("advice_{}", self.offset),
			&mut self.region,
			column,
			self.offset,
		)
	}

	/// Constrain two cells to be equal
	pub fn constrain_equal(
		&mut self, a_cell: AssignedCell<F, F>, b_cell: AssignedCell<F, F>,
	) -> Result<(), Error> {
		self.region.constrain_equal(a_cell.cell(), b_cell.cell())
	}

	/// Constrain a cell to be equal to a constant
	pub fn constrain_to_constant(
		&mut self, a_cell: AssignedCell<F, F>, constant: F,
	) -> Result<(), Error> {
		self.region.constrain_constant(a_cell.cell(), constant)
	}

	/// Enable selector at the current row offset
	pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
		selector.enable(&mut self.region, self.offset)
	}

	/// Increment the row offset
	pub fn next(&mut self) {
		self.offset += 1
	}
}

/// Number of advice columns in common config
pub const ADVICE: usize = 8;
/// Number of fixed columns in common config
pub const FIXED: usize = 10;

/// Common config for the whole circuit
#[derive(Clone, Debug)]
pub struct CommonConfig {
	/// Advice columns
	advice: [Column<Advice>; ADVICE],
	/// Fixed columns
	fixed: [Column<Fixed>; FIXED],
	/// Instance column
	instance: Column<Instance>,
}

impl CommonConfig {
	/// Create a new `CommonConfig` columns
	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
		let advice = [(); ADVICE].map(|_| meta.advice_column());
		let fixed = [(); FIXED].map(|_| meta.fixed_column());
		let instance = meta.instance_column();

		advice.map(|c| meta.enable_equality(c));
		fixed.map(|c| meta.enable_constant(c));
		meta.enable_equality(instance);

		Self { advice, fixed, instance }
	}
}

/// Trait for an atomic chip implementation
/// Each chip uses common config columns, but has its own selector
pub trait Chip<F: FieldExt> {
	/// Output of the synthesis
	type Output: Clone;
	/// Gate configuration, using common config columns
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector;
	/// Chip synthesis. This function can return an assigned cell to be used
	/// elsewhere in the circuit
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}

/// Chipset uses a collection of chips as primitives to build more abstract
/// circuits
pub trait Chipset<F: FieldExt> {
	/// Config used for synthesis
	type Config: Clone;
	/// Output of the synthesis
	type Output: Clone;
	/// Chipset synthesis. This function can have multiple smaller chips
	/// synthesised inside. Also can returns an assigned cell.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}

/// Calculate message hashes from given public keys and scores
pub fn calculate_message_hash<const N: usize, const S: usize>(
	pks: Vec<PublicKey>, scores: Vec<Vec<Scalar>>,
) -> (Scalar, Vec<Scalar>) {
	assert!(pks.len() == N);
	assert!(scores.len() == S);
	for score in &scores {
		assert!(score.len() == N);
	}

	let pks_x: Vec<Scalar> = pks.iter().map(|pk| pk.0.x.clone()).collect();
	let pks_y: Vec<Scalar> = pks.iter().map(|pk| pk.0.y.clone()).collect();
	let mut pk_sponge = PoseidonNativeSponge::new();
	pk_sponge.update(&pks_x);
	pk_sponge.update(&pks_y);
	let pks_hash = pk_sponge.squeeze();

	let messages = scores
		.into_iter()
		.map(|ops| {
			let mut scores_sponge = PoseidonNativeSponge::new();
			scores_sponge.update(&ops);
			let scores_hash = scores_sponge.squeeze();

			let final_hash_input =
				[pks_hash, scores_hash, Scalar::zero(), Scalar::zero(), Scalar::zero()];
			let final_hash = PoseidonNativeHasher::new(final_hash_input).permute()[0];
			final_hash
		})
		.collect();

	(pks_hash, messages)
}
