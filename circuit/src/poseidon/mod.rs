/// Native version of Poseidon
pub mod native;
/// Implementation of a Poseidon sponge
pub mod sponge;

use crate::{
	gadgets::absorb::copy_state, params::RoundParams, Chip, Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

/// Assign relevant constants to the circuit for the given round.
fn load_round_constants<F: FieldExt, const WIDTH: usize>(
	ctx: &mut RegionCtx<'_, F>, config: &CommonConfig, round_constants: &[F],
) -> Result<[Value<F>; WIDTH], Error> {
	let mut rc_values: [Value<F>; WIDTH] = [(); WIDTH].map(|_| Value::unknown());
	for i in 0..WIDTH {
		let rc = round_constants[ctx.offset() * WIDTH + i].clone();
		ctx.assign_fixed(config.fixed[i], rc)?;
		rc_values[i] = Value::known(rc);
	}
	Ok(rc_values)
}

/// A chip for full round poseidon permutation
pub struct FullRoundChip<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell array for the inputs.
	inputs: [AssignedCell<F, F>; WIDTH],
	/// Starting round offset
	round_offset: usize,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> FullRoundChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(inputs: [AssignedCell<F, F>; WIDTH], round_offset: usize) -> Self {
		Self { inputs, round_offset, _params: PhantomData }
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chip<F> for FullRoundChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Output = ([AssignedCell<F, F>; WIDTH], usize);

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		let state_columns: [Column<Advice>; WIDTH] = common.advice[0..WIDTH].try_into().unwrap();
		let rc_columns: [Column<Fixed>; WIDTH] = common.fixed[0..WIDTH].try_into().unwrap();

		meta.create_gate("full_round", |v_cells| {
			let state = state_columns.map(|c| v_cells.query_advice(c, Rotation::cur()));
			let round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation::cur()));
			// 1. step for the TRF.
			// AddRoundConstants step.
			let mut exprs = P::apply_round_constants_expr(&state, &round_constants);
			// Applying S-boxes for the full round.
			for i in 0..WIDTH {
				// 2. step for the TRF.
				// SubWords step, denoted by S-box.
				exprs[i] = P::sbox_expr(exprs[i].clone());
			}
			// 3. step for the TRF.
			// MixLayer step.
			exprs = P::apply_mds_expr(&exprs);

			let s_cells = v_cells.query_selector(selector);
			// It should be equal to the state in next row
			for i in 0..WIDTH {
				let next_state = v_cells.query_advice(state_columns[i], Rotation::next());
				exprs[i] = s_cells.clone() * (exprs[i].clone() - next_state);
			}
			exprs
		});

		selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let round_constants = P::round_constants();
		let full_rounds = P::full_rounds();
		let half_full_rounds = full_rounds / 2;
		let round_end = self.round_offset + half_full_rounds * WIDTH;
		let round_constants = &round_constants[self.round_offset..round_end];

		let res = layouter.assign_region(
			|| "full_rounds",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				// Assign initial state
				let mut state_cells = copy_state(&mut ctx, &common, &self.inputs)?;
				for _ in 0..half_full_rounds {
					ctx.enable(selector.clone())?;

					// Assign round constants
					let rc_values = load_round_constants(&mut ctx, &common, round_constants)?;

					// 1. step for the TRF.
					// AddRoundConstants step.
					let state_vals = state_cells.clone().map(|v| v.value().cloned());
					let mut next_state = P::apply_round_constants_val(&state_vals, &rc_values);
					for i in 0..WIDTH {
						// 2. step for the TRF.
						// SubWords step, denoted by S-box.
						next_state[i] = next_state[i].map(|s| P::sbox_f(s));
					}

					// 3. step for the TRF.
					// MixLayer step.
					next_state = P::apply_mds_val(&next_state);

					// Assign next state
					ctx.next();
					for i in 0..WIDTH {
						state_cells[i] = ctx.assign_advice(common.advice[i], next_state[i])?;
					}
				}
				Ok(state_cells)
			},
		)?;

		Ok((res, round_end))
	}
}

/// A chip for a partial round poseidon permutation
pub struct PartialRoundChip<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell array for the inputs.
	inputs: [AssignedCell<F, F>; WIDTH],
	/// Starting round offset
	round_offset: usize,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PartialRoundChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(inputs: [AssignedCell<F, F>; WIDTH], offset: usize) -> Self {
		Self { inputs, round_offset: offset, _params: PhantomData }
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chip<F> for PartialRoundChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Output = ([AssignedCell<F, F>; WIDTH], usize);

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		let state_columns: [Column<Advice>; WIDTH] = common.advice[0..WIDTH].try_into().unwrap();
		let rc_columns: [Column<Fixed>; WIDTH] = common.fixed[0..WIDTH].try_into().unwrap();

		meta.create_gate("partial_round", |v_cells| {
			let state = state_columns.map(|c| v_cells.query_advice(c, Rotation::cur()));
			let round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation::cur()));
			// 1. step for the TRF.
			// AddRoundConstants step.
			let mut exprs = P::apply_round_constants_expr(&state, &round_constants);
			// Applying single S-box for the partial round.
			// 2. step for the TRF.
			// SubWords step, denoted by S-box.
			exprs[0] = P::sbox_expr(exprs[0].clone());

			// 3. step for the TRF.
			// MixLayer step.
			exprs = P::apply_mds_expr(&exprs);

			let s_cells = v_cells.query_selector(selector);
			// It should be equal to the state in next row
			for i in 0..WIDTH {
				let next_state = v_cells.query_advice(state_columns[i], Rotation::next());
				exprs[i] = s_cells.clone() * (exprs[i].clone() - next_state);
			}

			exprs
		});

		selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let round_constants = P::round_constants();
		let partial_rounds = P::partial_rounds();
		let round_end = self.round_offset + partial_rounds * WIDTH;
		let round_constants = &round_constants[self.round_offset..round_end];

		let res = layouter.assign_region(
			|| "partial_rounds",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				let mut state_cells = copy_state(&mut ctx, common, &self.inputs)?;
				for _ in 0..partial_rounds {
					ctx.enable(selector.clone())?;

					// Assign round constants
					let rc_values = load_round_constants(&mut ctx, &common, round_constants)?;

					// 1. step for the TRF.
					// AddRoundConstants step.
					let state_vals = state_cells.clone().map(|v| v.value().cloned());
					let mut next_state = P::apply_round_constants_val(&state_vals, &rc_values);
					// 2. step for the TRF.
					// SubWords step, denoted by S-box.
					next_state[0] = next_state[0].map(|x| P::sbox_f(x));

					// 3. step for the TRF.
					// MixLayer step.
					next_state = P::apply_mds_val(&next_state);

					// Assign next state
					ctx.next();
					for i in 0..WIDTH {
						let new_state = next_state[i].clone();
						state_cells[i] = ctx.assign_advice(common.advice[i], new_state)?;
					}
				}
				Ok(state_cells)
			},
		)?;

		Ok((res, round_end))
	}
}

#[derive(Clone, Debug)]
/// Selectors for poseidon permutation
pub struct PoseidonConfig {
	fr_selector: Selector,
	pr_selector: Selector,
}

impl PoseidonConfig {
	/// Constructs a new config
	pub fn new(fr_selector: Selector, pr_selector: Selector) -> Self {
		Self { fr_selector, pr_selector }
	}
}

/// Constructs a chip structure for the circuit.
pub struct PoseidonChipset<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell array for the inputs.
	inputs: [AssignedCell<F, F>; WIDTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(inputs: [AssignedCell<F, F>; WIDTH]) -> Self {
		Self { inputs, _params: PhantomData }
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chipset<F> for PoseidonChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Config = PoseidonConfig;
	type Output = [AssignedCell<F, F>; WIDTH];

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// The Hades Design Strategy for Hashing.
		// Mixing rounds with half-full S-box layers and
		// rounds with partial S-box layers.
		// More detailed explanation for
		// The Round Function (TRF) and Hades:
		// https://eprint.iacr.org/2019/458.pdf#page=5

		let fr1 = FullRoundChip::<F, WIDTH, P>::new(self.inputs, 0);
		let (state1, round_end) = fr1.synthesize(
			&common,
			&config.fr_selector,
			layouter.namespace(|| "full_round_1"),
		)?;

		let pr = PartialRoundChip::<F, WIDTH, P>::new(state1, round_end);
		let (state2, round_end) = pr.synthesize(
			&common,
			&config.pr_selector,
			layouter.namespace(|| "partial_round_1"),
		)?;

		let fr2 = FullRoundChip::<F, WIDTH, P>::new(state2, round_end);
		let (state3, _) = fr2.synthesize(
			&common,
			&config.fr_selector,
			layouter.namespace(|| "full_round_2"),
		)?;

		Ok(state3)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		params::{hex_to_field, poseidon_bn254_5x5::Params},
		utils::{generate_params, prove_and_verify},
		CommonConfig,
	};
	use halo2::{
		circuit::{Layouter, SimpleFloorPlanner},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem, Error},
	};

	type FrChip = FullRoundChip<Fr, 5, Params>;
	type PrChip = PartialRoundChip<Fr, 5, Params>;

	#[derive(Clone)]
	struct PoseidonTesterConfig {
		common: CommonConfig,
		poseidon: PoseidonConfig,
	}

	#[derive(Clone)]
	struct PoseidonTester {
		inputs: [Value<Fr>; 5],
	}

	impl PoseidonTester {
		fn new(inputs: [Value<Fr>; 5]) -> Self {
			Self { inputs }
		}
	}

	impl Circuit<Fr> for PoseidonTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs: [Value::unknown(); 5] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let fr_selector = FrChip::configure(&common, meta);
			let pr_selector = PrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);

			Self::Config { common, poseidon }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let init_state = layouter.assign_region(
				|| "load_state",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
					for i in 0..5 {
						let init_state = self.inputs[i].clone();
						let asgn_state = ctx.assign_advice(config.common.advice[i], init_state)?;
						state[i] = Some(asgn_state);
					}
					Ok(state.map(|item| item.unwrap()))
				},
			)?;

			let poseidon = PoseidonChipset::<Fr, 5, Params>::new(init_state);
			let result_state = poseidon.synthesize(
				&config.common,
				&config.poseidon,
				layouter.namespace(|| "poseidon"),
			)?;
			for i in 0..5 {
				layouter.constrain_instance(result_state[i].cell(), config.common.instance, i)?;
			}
			Ok(())
		}
	}

	#[test]
	fn test_poseidon_x5_5() {
		// Testing 5x5 input.
		let inputs: [Value<Fr>; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| Value::known(hex_to_field(n)));

		let outputs: [Fr; 5] = [
			"0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
			"0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d",
			"0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907",
			"0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e",
			"0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7",
		]
		.map(|n| hex_to_field(n));

		let poseidon_tester = PoseidonTester::new(inputs);

		let k = 7;
		let prover = MockProver::run(k, &poseidon_tester, vec![outputs.to_vec()]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_poseidon_x5_5_production() {
		let inputs: [Value<Fr>; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| Value::known(hex_to_field(n)));

		let outputs: [Fr; 5] = [
			"0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
			"0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d",
			"0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907",
			"0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e",
			"0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7",
		]
		.map(|n| hex_to_field(n));

		let poseidon_tester = PoseidonTester::new(inputs);

		let k = 7;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, poseidon_tester, &[&outputs], rng).unwrap();
		assert!(res);
	}
}
