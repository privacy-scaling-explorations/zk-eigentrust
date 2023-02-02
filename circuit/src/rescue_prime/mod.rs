/// Native implementation
pub mod native;

/// Implementation of a RescuePrime sponge
pub mod sponge;

use crate::{gadgets::absorb::copy_state, params::RoundParams, Chip, CommonConfig, RegionCtx};
use halo2::{
	circuit::{AssignedCell, Layouter, Value},
	halo2curves::FieldExt,
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
		let rc = round_constants[(ctx.offset() / 2) * WIDTH + i].clone();
		ctx.assign_fixed(config.fixed[i], rc)?;
		rc_values[i] = Value::known(rc);
	}
	Ok(rc_values)
}

/// Constructs a chip structure for the circuit.
pub struct RescuePrimeChip<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell array for the inputs.
	inputs: [AssignedCell<F, F>; WIDTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> RescuePrimeChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// create a new chip.
	pub fn new(inputs: [AssignedCell<F, F>; WIDTH]) -> Self {
		Self { inputs, _params: PhantomData }
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chip<F> for RescuePrimeChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Output = [AssignedCell<F, F>; WIDTH];

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		let state_columns: [Column<Advice>; WIDTH] = common.advice[0..WIDTH].try_into().unwrap();
		let rc_columns: [Column<Fixed>; WIDTH] = common.fixed[0..WIDTH].try_into().unwrap();

		meta.create_gate("full_round", |v_cells| {
			//
			//   |  i  | round |    state     |   constants   |  selector  |
			//   |-----|-------|--------------|---------------|------------|
			//   |  0  |   1   |  state(1)    |    const(1)   |     *      |
			//   |  1  |       | sbox_invs(1) |               |            |
			//   |  2  |   2   |  state(2)    |    const(2)   |     *      |
			//   |  3  |       | sbox_invs(2) |               |            |
			//   |  4  |   3   |  state(3)    |    const(3)   |     *      |
			//                 ...

			let s_cells = v_cells.query_selector(selector);
			let mut state = state_columns.map(|c| v_cells.query_advice(c, Rotation::cur()));
			let sbox_inverts = state_columns.map(|c| v_cells.query_advice(c, Rotation::next()));
			let round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation::cur()));
			let next_round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation(2)));

			let mut exprs = vec![];

			// 1. step for the TRF
			// Applying S-boxes for the full round.
			for i in 0..WIDTH {
				state[i] = P::sbox_expr(state[i].clone());
			}

			// 2. step for the TRF
			// MixLayer step.
			state = P::apply_mds_expr(&state);

			// 3. step for the TRF
			// Apply RoundConstants
			state = P::apply_round_constants_expr(&state, &round_constants);

			// 4. step for the TRF
			// Applying S-box-inverse
			for i in 0..WIDTH {
				// x - sbox(sbox_inv(x)) = 0
				let org = P::sbox_expr(sbox_inverts[i].clone());
				let org_constraint = s_cells.clone() * (state[i].clone() - org);
				exprs.push(org_constraint);

				state[i] = sbox_inverts[i].clone();
			}

			// 5. step for the TRF
			// 2nd MixLayer step
			state = P::apply_mds_expr(&state);

			// 6. step for the TRF
			// Apply next RoundConstants
			state = P::apply_round_constants_expr(&state, &next_round_constants);

			// It should be equal to the state in next row
			for i in 0..WIDTH {
				let next_state = v_cells.query_advice(state_columns[i], Rotation(2));
				exprs.push(s_cells.clone() * (state[i].clone() - next_state));
			}

			exprs
		});

		selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let full_rounds = P::full_rounds();
		let round_constants = P::round_constants();

		let res = layouter.assign_region(
			|| "full_rounds",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				// Assign initial state
				let mut state_cells = copy_state(&mut ctx, &common, &self.inputs)?;

				// Assign initial round constants
				let mut rc_values = load_round_constants(&mut ctx, &common, &round_constants)?;

				for _ in 0..full_rounds - 1 {
					ctx.enable(selector.clone())?;

					let mut next_state = state_cells.clone().map(|v| v.value().cloned());
					// 1. step for the TRF.
					// S-box.
					for i in 0..WIDTH {
						next_state[i] = next_state[i].map(|s| P::sbox_f(s));
					}

					// 2. step for the TRF
					// Apply MDS
					next_state = P::apply_mds_val(&next_state);

					// 3. step for the TRF
					// Apply RoundConstants
					next_state = P::apply_round_constants_val(&next_state, &rc_values);

					// 4. step for the TRF
					// Apply S-box inverse
					ctx.next();
					for i in 0..WIDTH {
						next_state[i] = next_state[i].map(|s| P::sbox_inv_f(s));
						ctx.assign_advice(common.advice[i], next_state[i])?;
					}

					// 5. step for the TRF
					// Apply MDS for 2nd time
					next_state = P::apply_mds_val(&next_state);

					ctx.next();

					// 6. step for the TRF
					// Apply next RoundConstants
					rc_values = load_round_constants(&mut ctx, &common, &round_constants)?;
					next_state = P::apply_round_constants_val(&next_state, &rc_values);

					// Assign next state
					for i in 0..WIDTH {
						state_cells[i] = ctx.assign_advice(common.advice[i], next_state[i])?;
					}
				}
				Ok(state_cells)
			},
		)?;

		Ok(res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		params::{hex_to_field, rescue_prime_bn254_5x5::Params},
		utils::{generate_params, prove_and_verify},
		CommonConfig,
	};
	use halo2::{
		circuit::{Layouter, SimpleFloorPlanner},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	#[derive(Clone)]
	struct RescuePrimeTesterConfig {
		common: CommonConfig,
		selector: Selector,
	}

	#[derive(Clone)]
	struct RescuePrimeTester {
		inputs: [Value<Fr>; 5],
	}

	impl RescuePrimeTester {
		fn new(inputs: [Value<Fr>; 5]) -> Self {
			Self { inputs }
		}
	}

	impl Circuit<Fr> for RescuePrimeTester {
		type Config = RescuePrimeTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self::new([Value::unknown(); 5])
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let selector = RescuePrimeChip::<Fr, 5, Params>::configure(&common, meta);
			Self::Config { common, selector }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let init_state = layouter.assign_region(
				|| "load_state",
				|region| {
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

			let rescue_prime = RescuePrimeChip::<Fr, 5, Params>::new(init_state);
			let result_state = rescue_prime.synthesize(
				&config.common,
				&config.selector,
				layouter.namespace(|| "rescue_prime"),
			)?;

			for i in 0..5 {
				layouter.constrain_instance(result_state[i].cell(), config.common.instance, i)?;
			}

			Ok(())
		}
	}

	#[test]
	fn test_rescue_prime_5x5() {
		// Testing 5x5 input.
		let inputs: [Value<Fr>; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| Value::known(hex_to_field(n)));

		// Results taken from https://github.com/matter-labs/rescue-poseidon
		let outputs: [Fr; 5] = [
			"0x1a06ea09af4d8d61f991846f001ded4056feafcef55f1e9c4fd18100b8c7654f",
			"0x2f66d057b2bd9692f51e072013b8f320c5e6d7081070ffe7ca357e18e5faecf4",
			"0x177abf3b6a2e903adf4c71f18f744b55b39c487a9a4fd1a1d4aee381b99f357b",
			"0x1271bfa104c298efaccc1680be1b6e36cbf2c87ea789f2f79f7742bc16992235",
			"0x040f785abfad4da68331f9c884343fa6eecb07060ebcd96117862acebae5c3ac",
		]
		.map(|n| hex_to_field(n));

		let rescue_prime_tester = RescuePrimeTester::new(inputs);

		let k = 7;
		let prover = MockProver::run(k, &rescue_prime_tester, vec![outputs.to_vec()]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_rescue_prime_5x5_production() {
		let inputs: [Value<Fr>; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| Value::known(hex_to_field(n)));

		// Results taken from https://github.com/matter-labs/rescue-poseidon
		let outputs: [Fr; 5] = [
			"0x1a06ea09af4d8d61f991846f001ded4056feafcef55f1e9c4fd18100b8c7654f",
			"0x2f66d057b2bd9692f51e072013b8f320c5e6d7081070ffe7ca357e18e5faecf4",
			"0x177abf3b6a2e903adf4c71f18f744b55b39c487a9a4fd1a1d4aee381b99f357b",
			"0x1271bfa104c298efaccc1680be1b6e36cbf2c87ea789f2f79f7742bc16992235",
			"0x040f785abfad4da68331f9c884343fa6eecb07060ebcd96117862acebae5c3ac",
		]
		.map(|n| hex_to_field(n));

		let rescue_prime_tester = RescuePrimeTester::new(inputs);

		let k = 7;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, rescue_prime_tester, &[&outputs], rng).unwrap();
		assert!(res);
	}
}
