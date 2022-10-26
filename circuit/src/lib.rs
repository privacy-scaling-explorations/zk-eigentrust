//! The module for the main EigenTrust circuit.

#![feature(array_zip, array_try_map)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible, nonstandard_style, missing_docs, deprecated, unreachable_code,
	unreachable_patterns, absolute_paths_not_starting_with_crate, unsafe_code, clippy::panic,
	clippy::unnecessary_cast, clippy::cast_lossless, clippy::cast_possible_wrap
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// EDDSA signature scheme gadgets + native version
pub mod eddsa;
/// Common gadgets used across circuits
pub mod gadgets;
/// A module for defining round parameters and MDS matrix for hash
/// permutations
pub mod params;
/// Poseidon hash function gadgets + native version
pub mod poseidon;
/// Rescue Prime hash function gadgets + native version
pub mod rescue_prime;
/// Utilities for proving and verifying
pub mod utils;

use gadgets::{
	common::{CommonChip, CommonConfig},
	set::{FixedSetChip, FixedSetConfig},
	sum::{SumChip, SumConfig},
};
pub use halo2wrong;
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
	plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use params::RoundParams;
use poseidon::{PoseidonChip, PoseidonConfig};
use std::marker::PhantomData;

/// The halo2 columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	// Gadgets
	set: FixedSetConfig,
	common: CommonConfig,
	poseidon: PoseidonConfig<5>,
	sum: SumConfig,
	// EigenTrust columns
	temp: Column<Advice>,
	pub_ins: Column<Instance>,
}

/// The EigenTrust main circuit.
#[derive(Clone)]
pub struct EigenTrustCircuit<
	F: FieldExt,
	const SIZE: usize,
	const NUM_BOOTSTRAP: usize,
	P: RoundParams<F, 5>,
> {
	pubkey_v: Value<F>,
	epoch: Value<F>,
	iteration: Value<F>,
	secret_i: Value<F>,
	/// Opinions of peers j to the peer i (the prover).
	op_ji: [Value<F>; SIZE],
	/// Opinon from peer i (the prover) to the peer v (the verifyer).
	c_v: Value<F>,
	// Bootstrap data
	bootstrap_pubkeys: [F; NUM_BOOTSTRAP],
	boostrap_score: Value<F>,
	_params: PhantomData<P>,
}

impl<F: FieldExt, const S: usize, const B: usize, P: RoundParams<F, 5>>
	EigenTrustCircuit<F, S, B, P>
{
	/// Create a new EigenTrustCircuit.
	pub fn new(
		pubkey_v: F, epoch: F, iteration: F, secret_i: F, op_ji: [F; S], c_v: F,
		bootstrap_pubkeys: [F; B], boostrap_score: F,
	) -> Self {
		Self {
			pubkey_v: Value::known(pubkey_v),
			epoch: Value::known(epoch),
			iteration: Value::known(iteration),
			secret_i: Value::known(secret_i),
			op_ji: op_ji.map(|c| Value::known(c)),
			c_v: Value::known(c_v),
			bootstrap_pubkeys,
			boostrap_score: Value::known(boostrap_score),
			_params: PhantomData,
		}
	}

	/// Assign a Value to a column, used in the "temp" region
	pub fn assign_temp(
		column: Column<Advice>, name: &str, region: &mut Region<'_, F>, offset: &mut usize,
		value: Value<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let res = region.assign_advice(|| name, column, *offset, || value)?;
		*offset += 1;

		Ok(res)
	}

	/// Assinged a const to a cell in the column, used in the "temp" region
	pub fn assign_fixed(
		column: Column<Advice>, name: &str, region: &mut Region<'_, F>, offset: &mut usize,
		value: F,
	) -> Result<AssignedCell<F, F>, Error> {
		let res = region.assign_advice_from_constant(|| name, column, *offset, value)?;
		*offset += 1;

		Ok(res)
	}
}

impl<F: FieldExt, const S: usize, const B: usize, P: RoundParams<F, 5>> Circuit<F>
	for EigenTrustCircuit<F, S, B, P>
{
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pubkey_v: Value::unknown(),
			epoch: Value::unknown(),
			iteration: Value::unknown(),
			secret_i: Value::unknown(),
			op_ji: [Value::unknown(); S],
			c_v: Value::unknown(),
			bootstrap_pubkeys: self.bootstrap_pubkeys,
			boostrap_score: Value::unknown(),
			_params: PhantomData,
		}
	}

	/// Make the circuit config.
	fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
		let set = FixedSetChip::<_, B>::configure(meta);
		let common = CommonChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, P>::configure(meta);
		let sum = SumChip::<_, S>::configure(meta);

		let temp = meta.advice_column();
		let fixed = meta.fixed_column();
		let pub_ins = meta.instance_column();

		meta.enable_equality(temp);
		meta.enable_constant(fixed);
		meta.enable_equality(pub_ins);

		EigenTrustConfig { set, common, poseidon, sum, temp, pub_ins }
	}

	/// Synthesize the circuit.
	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<(), Error> {
		let (zero, ops, c_v, sk, epoch, iteration, bootstrap_score, pubkey_v, out_m_hash) =
			layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let mut offset = 0;
					let zero = Self::assign_fixed(
						config.temp,
						"zero",
						&mut region,
						&mut offset,
						F::zero(),
					)?;

					let sk = Self::assign_temp(
						config.temp, "op", &mut region, &mut offset, self.secret_i,
					)?;

					let epoch = Self::assign_temp(
						config.temp, "epoch", &mut region, &mut offset, self.epoch,
					)?;
					let iteration = Self::assign_temp(
						config.temp, "iteration", &mut region, &mut offset, self.iteration,
					)?;
					let bootstrap_score = Self::assign_temp(
						config.temp, "bootstrap_score", &mut region, &mut offset,
						self.boostrap_score,
					)?;
					let pubkey_v = Self::assign_temp(
						config.temp, "pubkey_v", &mut region, &mut offset, self.pubkey_v,
					)?;
					let c_v =
						Self::assign_temp(config.temp, "c_v", &mut region, &mut offset, self.c_v)?;

					let ops = self.op_ji.try_map::<_, Result<AssignedCell<F, F>, Error>>(|op| {
						Self::assign_temp(config.temp, "ops", &mut region, &mut offset, op)
					})?;

					let out_m_hash = region.assign_advice_from_instance(
						|| "m_hash",
						config.pub_ins,
						0,
						config.temp,
						offset,
					)?;

					Ok((
						zero, ops, c_v, sk, epoch, iteration, bootstrap_score, pubkey_v, out_m_hash,
					))
				},
			)?;

		let sum_chip = SumChip::new(ops);
		let t_i = sum_chip.synthesize(config.sum, layouter.namespace(|| "sum"))?;

		// Recreate the pubkey_i
		let inputs = [zero.clone(), zero.clone(), zero.clone(), zero.clone(), sk];
		let poseidon_pk = PoseidonChip::<_, 5, P>::new(inputs);
		let res = poseidon_pk.synthesize(
			config.poseidon.clone(),
			layouter.namespace(|| "poseidon_pk"),
		)?;
		let pubkey_i = res[0].clone();
		// Check the bootstrap set membership
		let set_membership = FixedSetChip::new(self.bootstrap_pubkeys, pubkey_i.clone());
		let is_bootstrap =
			set_membership.synthesize(config.set, layouter.namespace(|| "set_membership"))?;
		// Is the iteration equal to 0?
		let is_genesis = CommonChip::is_equal(
			iteration.clone(),
			zero,
			config.common,
			layouter.namespace(|| "is_eq"),
		)?;
		// Is this the bootstrap peer at genesis epoch?
		let is_bootstrap_and_genesis = CommonChip::and(
			is_bootstrap,
			is_genesis,
			config.common,
			layouter.namespace(|| "and"),
		)?;
		// Select the appropriate score, depending on the conditions
		let t_i_select = CommonChip::select(
			is_bootstrap_and_genesis,
			bootstrap_score,
			t_i,
			config.common,
			layouter.namespace(|| "select"),
		)?;

		let op_v = CommonChip::mul(t_i_select, c_v, config.common, layouter.namespace(|| "mul"))?;

		let m_hash_input = [epoch, iteration, op_v.clone(), pubkey_v, pubkey_i];
		let poseidon_m_hash = PoseidonChip::<_, 5, P>::new(m_hash_input);
		let res = poseidon_m_hash
			.synthesize(config.poseidon, layouter.namespace(|| "poseidon_m_hash"))?;
		let m_hash = res[0].clone();

		let is_zero_opinion = CommonChip::is_zero(
			op_v,
			config.common,
			layouter.namespace(|| "is_zero_opinion"),
		)?;

		let final_m_hash = CommonChip::select(
			is_zero_opinion,
			out_m_hash,
			m_hash,
			config.common,
			layouter.namespace(|| "m_hash_select"),
		)?;

		layouter.constrain_instance(final_m_hash.cell(), config.pub_ins, 0)?;

		Ok(())
	}
}
