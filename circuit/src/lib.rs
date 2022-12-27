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

use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Region, Value},
	plonk::{Advice, Column, Error, Fixed, Instance, Selector},
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
/// A module for defining round parameters and MDS matrix for hash
/// permutations
pub mod params;
/// Poseidon hash function gadgets + native version
pub mod poseidon;
/// Rescue Prime hash function gadgets + native version
pub mod rescue_prime;
/// Utilities for proving and verifying
pub mod utils;

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

	/// Enable selector at the current row offset
	pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
		selector.enable(&mut self.region, self.offset)
	}

	/// Increment the row offset
	pub fn next(&mut self) {
		self.offset += 1
	}
}
