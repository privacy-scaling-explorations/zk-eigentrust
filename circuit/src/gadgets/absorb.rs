use crate::{Chip, CommonConfig, RegionCtx};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

/// Copy the intermediate hash(poseidon, rescue_prime, ...) state
/// into the region
pub fn copy_state<F: FieldExt, const WIDTH: usize>(
	ctx: &mut RegionCtx<'_, F>, config: &CommonConfig, prev_state: &[AssignedCell<F, F>; WIDTH],
) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
	let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
	for i in 0..WIDTH {
		let new_state = ctx.copy_assign(config.advice[i], prev_state[i].clone())?;
		state[i] = Some(new_state);
	}
	Ok(state.map(|item| item.unwrap()))
}

/// A chip for absorbing the previous hash(poseidon, rescue_prime, ...) state
pub struct AbsorbChip<F: FieldExt, const WIDTH: usize> {
	prev_state: [AssignedCell<F, F>; WIDTH],
	state: [AssignedCell<F, F>; WIDTH],
}

impl<F: FieldExt, const WIDTH: usize> AbsorbChip<F, WIDTH> {
	/// Constructor for a chip
	pub fn new(
		prev_state: [AssignedCell<F, F>; WIDTH], state: [AssignedCell<F, F>; WIDTH],
	) -> Self {
		Self { prev_state, state }
	}
}

impl<F: FieldExt, const WIDTH: usize> Chip<F> for AbsorbChip<F, WIDTH> {
	type Output = [AssignedCell<F, F>; WIDTH];

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let absorb_selector = meta.selector();

		meta.create_gate("absorb", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));

			let s = v_cells.query_selector(absorb_selector);
			for i in 0..WIDTH {
				let hasher_exp = v_cells.query_advice(common.advice[i], Rotation::cur());
				let sponge_exp = v_cells.query_advice(common.advice[i], Rotation::next());
				let next_sponge_exp = v_cells.query_advice(common.advice[i], Rotation(2));
				let diff = next_sponge_exp - (sponge_exp + hasher_exp);
				exprs[i] = s.clone() * diff;
			}

			exprs
		});

		absorb_selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "absorb",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;

				// Load previous RescuePrime state
				let loaded_state = copy_state(&mut ctx, common, &self.prev_state)?;
				ctx.next();

				// Load next chunk
				let loaded_chunk = copy_state(&mut ctx, common, &self.state)?;
				ctx.next();

				// Calculate the next state to permute
				let columns: [Column<Advice>; WIDTH] =
					common.advice[0..WIDTH].to_vec().try_into().unwrap();
				let mut next_state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
				for i in 0..WIDTH {
					let chunk_state = &loaded_chunk[i];
					let pos_state = &loaded_state[i];
					let column = columns[i];
					let sum = chunk_state.value().and_then(|&s| {
						let pos_state_val = pos_state.value();
						pos_state_val.map(|&ps| s + ps)
					});
					let assigned_sum = ctx.assign_advice(column, sum)?;
					next_state[i] = Some(assigned_sum);
				}

				Ok(next_state.map(|x| x.unwrap()))
			},
		)
	}
}
