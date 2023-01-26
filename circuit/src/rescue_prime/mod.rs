use std::marker::PhantomData;

use halo2::{
	circuit::AssignedCell,
	halo2curves::FieldExt,
	plonk::{Advice, Column, Fixed},
	poly::Rotation,
};

use crate::{params::RoundParams, Chip};

/// Native implementation
pub mod native;

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

	fn configure(
		common: &crate::CommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> halo2::plonk::Selector {
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
		self, common: &crate::CommonConfig, selector: &halo2::plonk::Selector,
		layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		todo!()
	}
}
