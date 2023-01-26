use std::marker::PhantomData;

use halo2::{
	circuit::{AssignedCell, Layouter, Value},
	halo2curves::FieldExt,
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
	poly::Rotation,
};

use crate::{params::RoundParams, Chip, CommonConfig, RegionCtx};

/// Native implementation
pub mod native;

/// Copy the intermediate poseidon state into the region
fn copy_state<F: FieldExt, const WIDTH: usize>(
	ctx: &mut RegionCtx<'_, F>, config: &CommonConfig, prev_state: &[AssignedCell<F, F>; WIDTH],
) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
	let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
	for i in 0..WIDTH {
		let new_state = ctx.copy_assign(config.advice[i], prev_state[i].clone())?;
		state[i] = Some(new_state);
	}
	Ok(state.map(|item| item.unwrap()))
}

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

/// Constructs a chip structure for the circuit.
pub struct ResurPrimeChip<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell array for the inputs.
	inputs: [AssignedCell<F, F>; WIDTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> ResurPrimeChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// create a new chip.
	pub fn new(inputs: [AssignedCell<F, F>; WIDTH]) -> Self {
		Self { inputs, _params: PhantomData }
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chip<F> for ResurPrimeChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Output = [AssignedCell<F, F>; WIDTH];

	fn configure(common: &crate::CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		let state_columns: [Column<Advice>; WIDTH] = common.advice[0..WIDTH].try_into().unwrap();
		let rc_columns: [Column<Fixed>; WIDTH] = common.fixed[0..WIDTH].try_into().unwrap();

		meta.create_gate("full_round", |v_cells| {
			let state = state_columns.map(|c| v_cells.query_advice(c, Rotation::cur()));
			let round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation::cur()));
			let next_round_constants = rc_columns.map(|c| v_cells.query_fixed(c, Rotation::next()));
			let mut exprs = state;
			// 1. step for the TRF
			// Applying S-boxes for the full round.
			for i in 0..WIDTH {
				exprs[i] = P::sbox_expr(exprs[i].clone());
			}

			// 2. step for the TRF
			// MixLayer step.
			exprs = P::apply_mds_expr(&exprs);

			// 3. step for the TRF
			// Apply RoundConstants
			exprs = P::apply_round_constants_expr(&exprs, &round_constants);

			// 4. step for the TRF
			// Applying S-box-inverse
			for i in 0..WIDTH {
				exprs[i] = P::sbox_inv_expr(exprs[i].clone());
			}

			// 5. step for the TRF
			// 2nd MixLayer step
			exprs = P::apply_mds_expr(&exprs);

			// 6. step for the TRF
			// Apply next RoundConstants
			exprs = P::apply_round_constants_expr(&exprs, &next_round_constants);

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
		self, common: &crate::CommonConfig, selector: &Selector, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let full_rounds = P::full_rounds();
		let round_constants = P::round_constants();

		let res = layouter.assign_region(
			|| "full_rounds",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				// Assign initial state
				let mut state_cells = copy_state(&mut ctx, &common, &self.inputs)?;

				for _ in 0..full_rounds - 1 {
					ctx.enable(selector.clone())?;

					// Assign round constants
					let rc_values = load_round_constants(&mut ctx, &common, &round_constants)?;

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
					for i in 0..WIDTH {
						next_state[i] = next_state[i].map(|s| P::sbox_inv_f(s));
					}

					// 5. step for the TRF
					// Apply MDS for 2nd time
					next_state = P::apply_mds_val(&next_state);

					ctx.next();

					// 6. step for the TRF
					// Apply next RoundConstants
					let next_rc_values = load_round_constants(&mut ctx, &common, &round_constants)?;
					next_state = P::apply_round_constants_val(&next_state, &next_rc_values);

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
