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
use native::ReductionWitness;
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
	_native: PhantomData<N>,
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

		let p_prime = P::negative_wrong_modulus_decomposed();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("add", |v_cells| {
			let add_s = v_cells.query_selector(add_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let add_q_exp = v_cells.query_advice(quotient[0], Rotation::cur());
			// let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::c))
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			let mut t = [(); NUM_LIMBS].map(|_| Expression::Constant(N::zero()));
			for i in 0..NUM_LIMBS {
				t[i] = x_limb_exps[i].clone()
					+ y_limb_exps[i].clone()
					+ add_q_exp.clone() * p_prime[i];
			}

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t, result_exps.clone(), residues_exps);

			let native_constraint = P::compose_exp(x_limb_exps) + P::compose_exp(y_limb_exps)
				- P::compose_exp(result_exps);
			constraints.push(native_constraint);

			constraints.iter().map(|x| add_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		meta.create_gate("mul", |v_cells| {
			let mul_s = v_cells.query_selector(mul_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let mul_q_exp = quotient.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			let mut t = [(); NUM_LIMBS].map(|_| Expression::Constant(N::zero()));
			for k in 0..NUM_LIMBS {
				for i in 0..=k {
					let j = k - i;
					t[i + j] = t[i + j].clone()
						+ x_limb_exps[i].clone() * y_limb_exps[j].clone()
						+ mul_q_exp[j].clone() * p_prime[i];
				}
			}

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t, result_exps.clone(), residues_exps);

			let native_constraints = P::compose_exp(x_limb_exps) * P::compose_exp(y_limb_exps)
				- P::compose_exp(mul_q_exp) * p_in_n
				- P::compose_exp(result_exps);
			constraints.push(native_constraints);

			constraints.iter().map(|x| mul_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
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

	/// Assign cells for add operation.
	pub fn add(
		&self, x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "add_operation",
			|mut region: Region<'_, N>| {
				config.add_selector.enable(&mut region, 0);

				let mut assigned_x_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[None; NUM_LIMBS];
				let mut assigned_y_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[None; NUM_LIMBS];
				let mut assigned_intermediate: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[None; NUM_LIMBS];

				for i in 0..NUM_LIMBS {
					assigned_x_limbs = Some(x_limbs[i].copy_advice(
						|| format!("x_limb_{}", i),
						&mut region,
						config.x_limbs[i],
						0,
					)?);

					assigned_y_limbs = Some(y_limbs[i].copy_advice(
						|| format!("y_limb_{}", i),
						&mut region,
						config.y_limbs[i],
						0,
					)?);

					assigned_intermediate = Some(region.assign_advice(
						|| format!("intermediate_{}", i),
						&mut region,
						config.intermediate[i],
						0,
						rw.
					)?)
				}

				let mut assigned_residues = Vec::new();
				for i in 0..residues.len() {
					assigned_residues.push(residues[i].copy_advice(
						|| format!("residues_{}", i),
						&mut region,
						config.residues[i],
						0,
					)?)
				}

				let assigned_x_limbs = assigned_x_limbs.map(|x| x.unwrap());
				let assigned_y_limbs = assigned_y_limbs.map(|y| y.unwrap());
				let assigned_quotient =
					quotient.copy_advice(|| "quotient", &mut region, config.quotient[0], 0)?;
				let assigned_intermediate = assigned_intermediate.map(|x| x.unwrap());
			},
		)
	}
}
