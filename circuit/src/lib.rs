//! The module for the main EigenTrust circuit.

#![feature(array_try_map)]
#![feature(array_zip)]
#![allow(clippy::needless_range_loop)]

pub mod gadgets;
pub mod poseidon;
pub mod utils;

use std::marker::PhantomData;
use gadgets::{
	set::{FixedSetConfig, FixedSetChip},
	and::{AndConfig, AndChip},
	select::{SelectConfig, SelectChip},
	is_equal::{IsEqualConfig, IsEqualChip}};
pub use halo2wrong;
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{Layouter, SimpleFloorPlanner, Value, Region},
	plonk::{Circuit, ConstraintSystem, Error, Column, Advice, Selector, Instance},
	poly::{Rotation},
};
use poseidon::{PoseidonConfig, PoseidonChip, params::RoundParams};

/// The halo2 columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	// Gadgets
	set: FixedSetConfig,
	is_equal: IsEqualConfig,
	and: AndConfig,
	select: SelectConfig,
	poseidon: PoseidonConfig<5>,
	// EigenTrust columns
	temp: Column<Advice>,
	acc: Column<Advice>,
	lhs: Column<Advice>,
	rhs: Column<Advice>,
	acc_selector: Selector,
	opv_selector: Selector,
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
	secret_i: [Value<F>; 4],
	/// Opinions of peers j to the peer i (the prover).
	op_ji: [Value<F>; SIZE],
	/// Opinon from peer i (the prover) to the peer v (the verifyer).
	c_v: Value<F>,
	// Bootstrap data
	bootstrap_pubkeys: [Value<F>; NUM_BOOTSTRAP],
	boostrap_score: Value<F>,
	genesis_epoch: Value<F>,
	_params: PhantomData<P>,
}

impl<
	F: FieldExt,
	const S: usize,
	const B: usize,
	P: RoundParams<F, 5>,
> EigenTrustCircuit<F, S, B, P> {
	/// Create a new EigenTrustCircuit.
	pub fn new(
		pubkey_v: F,
		epoch: F,
		secret_i: [F; 4],
		op_ji: [F; S],
		c_v: F,
		bootstrap_pubkeys: [F; B],
		boostrap_score: F,
		genesis_epoch: F,
	) -> Self {
		Self {
			pubkey_v: Value::known(pubkey_v),
			epoch: Value::known(epoch),
			secret_i: secret_i.map(|val| Value::known(val)),
			op_ji: op_ji.map(|c| Value::known(c)),
			c_v: Value::known(c_v),
			bootstrap_pubkeys: bootstrap_pubkeys.map(|val| Value::known(val)),
			boostrap_score: Value::known(boostrap_score),
			genesis_epoch: Value::known(genesis_epoch),
			_params: PhantomData,
		}
	}
}

impl<
	F: FieldExt,
	const S: usize,
	const B: usize,
	P: RoundParams<F, 5>,
> Circuit<F> for EigenTrustCircuit<F, S, B, P> {
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pubkey_v: Value::unknown(),
			epoch: Value::unknown(),
			secret_i: [Value::unknown(); 4],
			op_ji: [Value::unknown(); S],
			c_v: Value::unknown(),
			bootstrap_pubkeys: [Value::unknown(); B],
			boostrap_score: Value::unknown(),
			genesis_epoch: Value::unknown(),
			_params: PhantomData,
		}
	}

	/// Make the circuit config.
	fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
		let set = FixedSetChip::<_, B>::configure(meta);
		let is_equal = IsEqualChip::configure(meta);
		let and = AndChip::configure(meta);
		let select = SelectChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, P>::configure(meta);

		let acc = meta.advice_column();
		let acc_selector = meta.selector();

		let lhs = meta.advice_column();
		let rhs = meta.advice_column();
		let opv_selector = meta.selector();

		let temp = meta.advice_column();

		let pub_ins = meta.instance_column();

		meta.create_gate("acc", |v_cells| {
			let acc_prev = v_cells.query_advice(acc, Rotation::prev());
			let acc_cur = v_cells.query_advice(acc, Rotation::cur());
			let acc_next = v_cells.query_advice(acc, Rotation::cur());

			let s = v_cells.query_selector(acc_selector);

			vec![s * (acc_prev + acc_cur - acc_next)]
		});

		meta.create_gate("op_v", |v_cells| {
			let lhs_exp = v_cells.query_advice(lhs, Rotation::cur());
			let rhs_exp = v_cells.query_advice(rhs, Rotation::cur());
			let out = v_cells.query_advice(lhs, Rotation::next());
			let s = v_cells.query_selector(opv_selector);

			vec![s * (lhs_exp * rhs_exp - out)]
		});

		EigenTrustConfig {
			set,
			is_equal,
			and,
			select,
			poseidon,
			acc,
			lhs,
			rhs,
			acc_selector,
			opv_selector,
			temp,
			pub_ins,
		}
	}

	/// Synthesize the circuit.
	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<F>,
	) -> Result<(), Error> {
		let (zero, sk, epoch, genesis_epoch, bootstrap_score, pubkey_v) = layouter.assign_region(
			|| "temp",
			|mut region: Region<'_, F>| {
				let zero = region.assign_advice(|| "poseidon_pk_0", config.temp, 0, || Value::known(F::zero()))?;
				let one = region.assign_advice(|| "poseidon_pk_1", config.temp, 1, || self.secret_i[0])?;
				let two = region.assign_advice(|| "poseidon_pk_2", config.temp, 2, || self.secret_i[1])?;
				let three = region.assign_advice(|| "poseidon_pk_3", config.temp, 3, || self.secret_i[2])?;
				let four = region.assign_advice(|| "poseidon_pk_4", config.temp, 4, || self.secret_i[3])?;

				let epoch  = region.assign_advice(|| "epoch", config.temp, 5, || self.epoch)?;
				let genesis_epoch = region.assign_advice(|| "genesis_epoch", config.temp, 6, || self.genesis_epoch)?;
				let bootstrap_score = region.assign_advice(|| "bootstrap_score", config.temp, 7, || self.boostrap_score)?;
				let pubkey_v = region.assign_advice(|| "pubkey_v", config.temp, 8, || self.pubkey_v)?;
				Ok((zero, [one, two, three, four], epoch, genesis_epoch, bootstrap_score, pubkey_v))
			}
		)?;

		let t_i = layouter.assign_region(
			|| "t_i",
			|mut region: Region<'_, F>| {
				let mut accumulated_sum = region.assign_advice(|| "t_i_acc_0", config.acc, 0, || self.op_ji[0])?;

				for i in 1..(S - 1) {
					config.acc_selector.enable(&mut region, i)?;
					let next = accumulated_sum.value().cloned() + self.op_ji[i];
					accumulated_sum = region.assign_advice(|| "t_i_acc_i", config.acc, i, || next)?;
				}

				let next = accumulated_sum.value().cloned() + self.op_ji[S - 1];
				accumulated_sum = region.assign_advice(|| "t_i_acc_n", config.acc, S - 1, || next)?;

				Ok(accumulated_sum)
			}
		)?;

		// Recreate the pubkey_i
		let inputs = [zero.clone(), sk[0].clone(), sk[1].clone(), sk[2].clone(), sk[3].clone()];
		let poseidon_pk = PoseidonChip::<_, 5, P>::new(inputs);
		let res = poseidon_pk.synthesize(&config.poseidon, layouter.namespace(|| "poseidon_pk"))?;
		let pubkey_i = res[0].clone();

		// Check the bootstrap set membership
		let set_membership = FixedSetChip::new(self.bootstrap_pubkeys, pubkey_i.clone());
		let is_bootstrap = set_membership.synthesize(config.set, layouter.namespace(|| "set_membership"))?;

		// Is the epoch equal to the genesis epoch?
		let is_eq_chip = IsEqualChip::new(epoch.clone(), genesis_epoch);
		let is_genesis = is_eq_chip.synthesize(config.is_equal, layouter.namespace(|| "is_eq"))?;

		// Is this the bootstrap peer at genesis epoch?
		let and_chip = AndChip::new(is_bootstrap, is_genesis);
		let is_bootstrap_and_genesis = and_chip.synthesize(config.and, layouter.namespace(|| "and"))?;

		// Select the appropriate score, depending on the conditions
		let select_chip = SelectChip::new(is_bootstrap_and_genesis, bootstrap_score, t_i);
		let t_i_select = select_chip.synthesize(config.select, layouter.namespace(|| "select"))?;

		let op_v = layouter.assign_region(
			|| "op_v",
			|mut region: Region<'_, F>| {
				config.opv_selector.enable(&mut region, 0)?;
				let lhs = t_i_select.copy_advice(|| "t_i_final", &mut region, config.lhs, 0)?;
				let rhs = region.assign_advice(|| "t_i", config.rhs, 0, || self.c_v)?;
				
				let out = lhs.value().cloned() * rhs.value();

				let out_assigned = region.assign_advice(|| "op_v", config.lhs, 1, || out)?;

				Ok(out_assigned)
			}
		)?;

		let m_hash_input = [zero, epoch, op_v, pubkey_v, pubkey_i];
		let poseidon_m_hash = PoseidonChip::<_, 5, P>::new(m_hash_input);
		let res = poseidon_m_hash.synthesize(&config.poseidon, layouter.namespace(|| "poseidon_m_hash"))?;
		let m_hash = res[0].clone();

		layouter.constrain_instance(m_hash.cell(), config.pub_ins, 0)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{dev::MockProver, arithmetic::Field},
	};
	use poseidon::params::bn254_5x5::Params5x5Bn254;
	use rand::thread_rng;
	use utils::{generate_params, prove_and_verify};

	const SIZE: usize = 12;
	const NUM_BOOTSTRAP: usize = 2;
	const MAX_SCORE: u64 = 100000000;

	#[test]
	fn test_eigen_trust_verify() {
		let k = 18;

		let mut rng = thread_rng();
		let pubkey_v = Fr::random(&mut rng);

		let epoch = Fr::one();
		let sk = [(); 4].map(|_| Fr::random(&mut rng));

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let bootstrap_pubkeys = [(); NUM_BOOTSTRAP].map(|_| Fr::random(&mut rng));
		let bootstrap_score = Fr::from(MAX_SCORE);
		let genesis_epoch = Fr::one();

		let eigen_trust = EigenTrustCircuit::<Fr, SIZE, NUM_BOOTSTRAP, Params5x5Bn254>::new(
			pubkey_v,
			epoch,
			sk,
			op_ji,
			c_v,
			bootstrap_pubkeys,
			bootstrap_score,
			genesis_epoch,
		);

		let prover = match MockProver::<Fr>::run(k, &eigen_trust, vec![vec![]]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eigen_trust_production_prove_verify() {
		let k = 18;

		let mut rng = thread_rng();
		let pubkey_v = Fr::random(&mut rng);

		let epoch = Fr::one();
		let sk = [(); 4].map(|_| Fr::random(&mut rng));

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let bootstrap_pubkeys = [(); NUM_BOOTSTRAP].map(|_| Fr::random(&mut rng));
		let bootstrap_score = Fr::from(MAX_SCORE);
		let genesis_epoch = Fr::one();

		let eigen_trust = EigenTrustCircuit::<Fr, SIZE, NUM_BOOTSTRAP, Params5x5Bn254>::new(
			pubkey_v,
			epoch,
			sk,
			op_ji,
			c_v,
			bootstrap_pubkeys,
			bootstrap_score,
			genesis_epoch,
		);

		let params = generate_params(k);
		prove_and_verify::<Bn256, _, _>(params, eigen_trust, &[&[]], &mut rng).unwrap();
	}
}
