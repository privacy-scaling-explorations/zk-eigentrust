/// Native implementation for the non-native field arithmetic
pub mod native;
/// RNS operations for the non-native field arithmetic
pub mod rns;

use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
	poly::Rotation,
};
use rns::RnsParams;
use std::marker::PhantomData;

struct IntegerConfig<const NUM_LIMBS: usize> {
	x_limbs: [Column<Advice>; NUM_LIMBS],
	y_limbs: [Column<Advice>; NUM_LIMBS],
	quotient: [Column<Advice>; NUM_LIMBS],
	intermediate: [Column<Advice>; NUM_LIMBS],
	residues: Vec<Column<Advice>>,
	add_selector: Selector,
	mul_selector: Selector,
}

struct IntegerChip<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	x_limbs: [AssignedCell<N, N>; NUM_LIMBS],
	y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
	quotient: [AssignedCell<N, N>; NUM_LIMBS],
	intermediate: [AssignedCell<N, N>; NUM_LIMBS],
	residues: Vec<AssignedCell<N, N>>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub fn configure(meta: &mut ConstraintSystem<N>) -> IntegerConfig<NUM_LIMBS> {
		let x_limbs = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let y_limbs = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let quotient = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let intermediate = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let residues: Vec<Column<Advice>> =
			vec![(); NUM_LIMBS / 2].iter().map(|_| meta.advice_column()).collect();
		let add_selector = meta.selector();
		let mul_selector = meta.selector();

		let lsh_one = P::left_shifters()[1];
		let lsh_two = P::left_shifters()[2];
		let p_prime = P::negative_wrong_modulus_decomposed();

		meta.create_gate("reduction", |v_cells| {
			let limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let quotient_exps = quotient.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let intermediate_exps = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(x, Rotation::cur())).collect();

			let mut v = Expression::Constant(N::zero());
			let mut constraints = Vec::new();
			for i in (0..NUM_LIMBS).step_by(2) {
				let (t_lo, t_hi) = (intermediate_exps[i], intermediate_exps[i + 1]);
				let (r_lo, r_hi) = (limb_exps[i], limb_exps[i + 1]);
				let res =
					t_lo + t_hi * lsh_one - r_lo - r_hi * lsh_one - residues_exps[i / 2] * lsh_two
						+ v;
				v = residues[i / 2];
				constraints.push(res);
			}

			constraints
		});

		meta.create_gate("add", |v_cells| {
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let add_q_exp = v_cells.query_advice(quotient[0], Rotation::cur());
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(x, Rotation::cur())).collect();

			let mut t = [Expression::Constant(N::zero()); NUM_LIMBS];
			for i in 0..NUM_LIMBS {
				t[i] = x_limb_exps[i] + y_limb_exps[i] + p_prime[i] * add_q_exp;
			}

			// REDUCTION CONSTRAINTS
			P::constrain_binary_crt_exp(t, result_exps, residues_exps);
		});

		meta.create_gate("mul", |v_cells| {
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let mul_q_exp = quotient.map(|x| query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(x, Rotation::cur())).collect();

			let mut t = [Expression::Constant(N::zero()); NUM_LIMBS];
			for k in 0..NUM_LIMBS {
				for i in 0..=k {
					let j = k - i;
					t[i + j] = t[i + j] + x_limbs[i] * y_limbs[j] + p_prime[i] * q[j];
				}
			}

			// REDUCTION CONSTRAINTS
			P::constrain_binary_crt_exp(t, result_exps, residues_exps);
		});

		IntegerConfig {
			x_limbs,
			y_limbs,
			quotient,
			intermediate,
			residues,
			add_selector,
			mul_selector,
		}
	}
}
