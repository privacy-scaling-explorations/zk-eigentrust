/// Native implementation for the non-native field arithmetic
pub mod native;
/// RNS operations for the non-native field arithmetic
pub mod rns;

use self::native::Integer;
use crate::{Chip, CommonConfig, RegionCtx};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use native::{Quotient, ReductionWitness};
use rns::RnsParams;
use std::marker::PhantomData;

/// Chip structure for the IntegerAssign.
pub struct IntegerAssign<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}
impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerAssign<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Assigns given values and their reduction witnesses
	pub fn assign(
		x_opt: Option<&[AssignedCell<N, N>; NUM_LIMBS]>, y: &[AssignedCell<N, N>; NUM_LIMBS],
		reduction_witness: &ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, common: &CommonConfig,
		ctx: &mut RegionCtx<N>,
	) -> Result<AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>, Error> {
		for i in 0..NUM_LIMBS {
			if x_opt.is_some() {
				let x = x_opt.unwrap();
				ctx.copy_assign(common.advice[i + NUM_LIMBS], x[i].clone())?;
			}
			ctx.copy_assign(common.advice[i], y[i].clone())?;
		}
		ctx.next();

		match &reduction_witness.quotient {
			Quotient::Short(n) => {
				ctx.assign_advice(common.advice[NUM_LIMBS], Value::known(*n))?;
			},
			Quotient::Long(n) => {
				for i in 0..NUM_LIMBS {
					ctx.assign_advice(common.advice[i + NUM_LIMBS], Value::known(n.limbs[i]))?;
				}
			},
		}
		for i in 0..reduction_witness.residues.len() {
			ctx.assign_advice(
				common.advice[i],
				Value::known(reduction_witness.residues[i]),
			)?;
		}

		ctx.next();
		let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			ctx.assign_advice(
				common.advice[i],
				Value::known(reduction_witness.intermediate[i]),
			)?;
			assigned_result[i] = Some(ctx.assign_advice(
				common.advice[i + NUM_LIMBS],
				Value::known(reduction_witness.result.limbs[i]),
			)?);
		}
		let assigned_result = AssignedInteger::new(
			reduction_witness.result.clone(),
			assigned_result.map(|x| x.unwrap()),
		);
		Ok(assigned_result)
	}
}

/// Chip structure for the IntegerReduce.
pub struct IntegerReduceChip<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assigned integer
	assigned_integer: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerReduceChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new reduce chip
	pub fn new(assigned_integer: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { assigned_integer, _native: PhantomData, _wrong: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chip<N>
	for IntegerReduceChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<N>) -> Selector {
		let selector = meta.selector();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("reduce", |v_cells| {
			let s = v_cells.query_selector(selector);
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut residues_exp = Vec::new();
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);
			for i in 0..NUM_LIMBS {
				limbs_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation::cur()));
				t_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation(2)));
				result_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation(2)));
			}
			for i in 0..NUM_LIMBS / 2 {
				residues_exp.push(v_cells.query_advice(common.advice[i], Rotation::next()));
			}
			let reduce_q_exp = v_cells.query_advice(common.advice[NUM_LIMBS], Rotation::next());

			let t_exp = t_exp.map(|x| x.unwrap());
			let limbs_exp = limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			// NATIVE CONSTRAINTS
			let native_constraint =
				P::compose_exp(limbs_exp) - reduce_q_exp * p_in_n - P::compose_exp(result_exp);
			constraints.push(native_constraint);

			constraints.iter().map(|x| s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});
		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let reduction_witness = self.assigned_integer.integer.reduce();
		layouter.assign_region(
			|| "reduce_operation",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;
				IntegerAssign::assign(
					None, &self.assigned_integer.integer_limbs, &reduction_witness, &common,
					&mut ctx,
				)
			},
		)
	}
}

/// Chip structure for the IntegerAdd.
pub struct IntegerAddChip<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assigned integer x
	x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	// Assigned integer y
	y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerAddChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new add chip.
	pub fn new(
		x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, _native: PhantomData, _wrong: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chip<N>
	for IntegerAddChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<N>) -> Selector {
		let selector = meta.selector();
		meta.create_gate("add", |v_cells| {
			let s = v_cells.query_selector(selector);
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut residues_exp = Vec::new();
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);
			for i in 0..NUM_LIMBS {
				x_limbs_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur()));
				y_limbs_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation::cur()));
				t_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation(2)));
				result_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation(2)));
			}
			for i in 0..NUM_LIMBS / 2 {
				residues_exp.push(v_cells.query_advice(common.advice[i], Rotation::next()));
			}
			let _add_q_exp = v_cells.query_advice(common.advice[NUM_LIMBS], Rotation::next());

			let t_exp = t_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			// NATIVE CONSTRAINTS
			let native_constraint = P::compose_exp(x_limbs_exp) + P::compose_exp(y_limbs_exp)
				- P::compose_exp(result_exp);
			constraints.push(native_constraint);

			constraints.iter().map(|x| s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});
		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let reduction_witness = self.x.integer.add(&self.y.integer);
		layouter.assign_region(
			|| "add_operation",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;
				IntegerAssign::assign(
					Some(&self.x.integer_limbs),
					&self.y.integer_limbs,
					&reduction_witness,
					&common,
					&mut ctx,
				)
			},
		)
	}
}

/// Chip structure for the IntegerSub.
pub struct IntegerSubChip<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assigned integer x
	x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	// Assigned integer y
	y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerSubChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new sub chip
	pub fn new(
		x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, _native: PhantomData, _wrong: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chip<N>
	for IntegerSubChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<N>) -> Selector {
		let selector = meta.selector();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("sub", |v_cells| {
			let s = v_cells.query_selector(selector);
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut residues_exp = Vec::new();
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);
			for i in 0..NUM_LIMBS {
				x_limbs_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur()));
				y_limbs_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation::cur()));
				t_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation(2)));
				result_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation(2)));
			}
			for i in 0..NUM_LIMBS / 2 {
				residues_exp.push(v_cells.query_advice(common.advice[i], Rotation::next()));
			}
			let sub_q_exp = v_cells.query_advice(common.advice[NUM_LIMBS], Rotation::next());

			let t_exp = t_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			// NATIVE CONSTRAINTS
			let native_constraint = P::compose_exp(x_limbs_exp) - P::compose_exp(y_limbs_exp)
				+ sub_q_exp * p_in_n
				- P::compose_exp(result_exp);
			constraints.push(native_constraint);

			constraints.iter().map(|x| s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});
		selector
	}

	/// Assign cells for sub operation.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let reduction_witness = self.x.integer.sub(&self.y.integer);
		layouter.assign_region(
			|| "sub_operation",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;
				IntegerAssign::assign(
					Some(&self.x.integer_limbs),
					&self.y.integer_limbs,
					&reduction_witness,
					&common,
					&mut ctx,
				)
			},
		)
	}
}

/// Chip structure for the IntegerMul.
pub struct IntegerMulChip<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assigned integer x
	x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	// Assigned integer y
	y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerMulChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new mul chip
	pub fn new(
		x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, _native: PhantomData, _wrong: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chip<N>
	for IntegerMulChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<N>) -> Selector {
		let selector = meta.selector();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("mul", |v_cells| {
			let s = v_cells.query_selector(selector);
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut mul_q_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut residues_exp = Vec::new();
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);
			for i in 0..NUM_LIMBS {
				x_limbs_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur()));
				y_limbs_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation::cur()));
				mul_q_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::next()));
				t_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation(2)));
				result_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation(2)));
			}
			for i in 0..NUM_LIMBS / 2 {
				residues_exp.push(v_cells.query_advice(common.advice[i], Rotation::next()));
			}
			let t_exp = t_exp.map(|x| x.unwrap());
			let mul_q_exp = mul_q_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			// NATIVE CONSTRAINTS
			let native_constraints = P::compose_exp(x_limbs_exp) * P::compose_exp(y_limbs_exp)
				- P::compose_exp(mul_q_exp) * p_in_n
				- P::compose_exp(result_exp);
			constraints.push(native_constraints);

			constraints.iter().map(|x| s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});
		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let reduction_witness = self.x.integer.mul(&self.y.integer);
		layouter.assign_region(
			|| "mul_operation",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;
				IntegerAssign::assign(
					Some(&self.x.integer_limbs),
					&self.y.integer_limbs,
					&reduction_witness,
					&common,
					&mut ctx,
				)
			},
		)
	}
}

/// Chip structure for the IntegerDiv.
pub struct IntegerDivChip<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assigned integer x
	x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	// Assigned integer y
	y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerDivChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new div chip
	pub fn new(
		x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, _native: PhantomData, _wrong: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chip<N>
	for IntegerDivChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<N>) -> Selector {
		let selector = meta.selector();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("div", |v_cells| {
			let s = v_cells.query_selector(selector);
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut div_q_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut residues_exp = Vec::new();
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);
			for i in 0..NUM_LIMBS {
				x_limbs_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur()));
				y_limbs_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation::cur()));
				div_q_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::next()));
				t_exp[i] = Some(v_cells.query_advice(common.advice[i], Rotation(2)));
				result_exp[i] =
					Some(v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation(2)));
			}
			for i in 0..NUM_LIMBS / 2 {
				residues_exp.push(v_cells.query_advice(common.advice[i], Rotation::next()));
			}
			let t_exp = t_exp.map(|x| x.unwrap());
			let div_q_exp = div_q_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			//NATIVE CONSTRAINTS
			let native_constraints = P::compose_exp(y_limbs_exp) * P::compose_exp(result_exp)
				- P::compose_exp(x_limbs_exp)
				- P::compose_exp(div_q_exp) * p_in_n;
			constraints.push(native_constraints);

			constraints.iter().map(|x| s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});
		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let reduction_witness = self.x.integer.div(&self.y.integer);
		layouter.assign_region(
			|| "div_operation",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;
				IntegerAssign::assign(
					Some(&self.x.integer_limbs),
					&self.y.integer_limbs,
					&reduction_witness,
					&common,
					&mut ctx,
				)
			},
		)
	}
}

#[derive(Debug, Clone)]
/// Structure for the `AssignedInteger`.
pub struct AssignedInteger<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Original value of the assigned integer.
	pub(crate) integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	// Limbs of the assigned integer.
	pub(crate) integer_limbs: [AssignedCell<N, N>; NUM_LIMBS],
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a new `AssignedInteger` given its values
	pub fn new(
		integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		integer_limbs: [AssignedCell<N, N>; NUM_LIMBS],
	) -> Self {
		Self { integer, integer_limbs }
	}
}

#[cfg(test)]
mod test {
	use super::{native::Integer, rns::Bn256_4_68, *};
	use crate::{
		utils::{generate_params, prove_and_verify},
		CommonConfig,
	};
	use halo2::{
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fq, Fr},
		plonk::Circuit,
	};
	use num_bigint::BigUint;
	use std::str::FromStr;

	#[derive(Clone)]
	enum Gadgets {
		Reduce,
		Add,
		Sub,
		Mul,
		Div,
	}

	#[derive(Clone, Debug)]
	struct TestConfig<const NUM_LIMBS: usize> {
		common: CommonConfig,
		reduce_selector: Selector,
		add_selector: Selector,
		sub_selector: Selector,
		mul_selector: Selector,
		div_selector: Selector,
	}

	#[derive(Clone)]
	struct TestCircuit<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: Option<Integer<W, N, NUM_LIMBS, NUM_BITS, P>>,
		gadget: Gadgets,
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
		TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
			y: Option<Integer<W, N, NUM_LIMBS, NUM_BITS, P>>, gadget: Gadgets,
		) -> Self {
			Self { x, y, gadget }
		}
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Circuit<N>
		for TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		type Config = TestConfig<NUM_LIMBS>;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig<NUM_LIMBS> {
			let common = CommonConfig::new(meta);
			let reduce_selector =
				IntegerReduceChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let add_selector =
				IntegerAddChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let sub_selector =
				IntegerSubChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let mul_selector =
				IntegerMulChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let div_selector =
				IntegerDivChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);

			TestConfig {
				common,
				reduce_selector,
				add_selector,
				sub_selector,
				mul_selector,
				div_selector,
			}
		}

		fn synthesize(
			&self, config: TestConfig<NUM_LIMBS>, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let (x_limbs_assigned, y_limbs_assigned) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut y_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_advice(
							config.common.advice[0],
							Value::known(self.x.limbs[i]),
						)?;
						x_limbs[i] = Some(x);
						if self.y.is_some() {
							let y_unwrapped = self.y.clone().unwrap();
							let y = ctx.assign_advice(
								config.common.advice[1],
								Value::known(y_unwrapped.limbs[i]),
							)?;
							y_limbs[i] = Some(y);
						}
						ctx.next();
					}
					Ok((x_limbs, y_limbs))
				},
			)?;

			let mut result = None;
			match self.gadget {
				Gadgets::Reduce => {
					let assigned_integer =
						AssignedInteger::new(self.x.clone(), x_limbs_assigned.map(|x| x.unwrap()));
					let chip = IntegerReduceChip::new(assigned_integer);
					result = Some(chip.synthesize(
						&config.common,
						&config.reduce_selector,
						layouter.namespace(|| "reduce"),
					)?);
				},

				Gadgets::Add => {
					let x_assigned =
						AssignedInteger::new(self.x.clone(), x_limbs_assigned.map(|x| x.unwrap()));
					let y_assigned = AssignedInteger::new(
						self.y.clone().unwrap(),
						y_limbs_assigned.map(|x| x.unwrap()),
					);
					let chip = IntegerAddChip::new(x_assigned, y_assigned);
					result = Some(chip.synthesize(
						&config.common,
						&config.add_selector,
						layouter.namespace(|| "add"),
					)?);
				},
				Gadgets::Sub => {
					let x_assigned =
						AssignedInteger::new(self.x.clone(), x_limbs_assigned.map(|x| x.unwrap()));
					let y_assigned = AssignedInteger::new(
						self.y.clone().unwrap(),
						y_limbs_assigned.map(|x| x.unwrap()),
					);
					let chip = IntegerSubChip::new(x_assigned, y_assigned);
					result = Some(chip.synthesize(
						&config.common,
						&config.sub_selector,
						layouter.namespace(|| "sub"),
					)?);
				},
				Gadgets::Mul => {
					let x_assigned =
						AssignedInteger::new(self.x.clone(), x_limbs_assigned.map(|x| x.unwrap()));
					let y_assigned = AssignedInteger::new(
						self.y.clone().unwrap(),
						y_limbs_assigned.map(|x| x.unwrap()),
					);
					let chip = IntegerMulChip::new(x_assigned, y_assigned);

					result = Some(chip.synthesize(
						&config.common,
						&config.mul_selector,
						layouter.namespace(|| "mul"),
					)?);
				},

				Gadgets::Div => {
					let x_assigned =
						AssignedInteger::new(self.x.clone(), x_limbs_assigned.map(|x| x.unwrap()));
					let y_assigned = AssignedInteger::new(
						self.y.clone().unwrap(),
						y_limbs_assigned.map(|x| x.unwrap()),
					);
					let chip = IntegerDivChip::new(x_assigned, y_assigned);

					result = Some(chip.synthesize(
						&config.common,
						&config.div_selector,
						layouter.namespace(|| "div"),
					)?);
				},
			};
			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(
					result.clone().unwrap().integer_limbs[i].cell(),
					config.common.instance,
					i,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_reduce_smaller() {
		// Testing reduce with input smaller than wrong modulus.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let res = a.reduce();
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), None, Gadgets::Reduce);

		let k = 5;
		let p_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_reduce_bigger() {
		// Testing reduce with input bigger than wrong modulus.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208584192938236132395034328372853987091237643",
		)
		.unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let res = a.reduce();
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), None, Gadgets::Reduce);

		let k = 5;
		let p_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_add_two_numbers() {
		// Testing add with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("3534512312312312314235346475676435").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let res = a.add(&b);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), Gadgets::Add);

		let k = 5;
		let p_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_two_numbers() {
		// Testing mul with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("121231231231231231231231231233").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let res = a.mul(&b);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), Gadgets::Mul);
		let k = 5;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_mul_production() {
		let a_big = BigUint::from_str("4057452572750886963137894").unwrap();
		let b_big = BigUint::from_str("4057452572750112323238869612312354423534563456363213137894")
			.unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let res_add = a.add(&b);
		let res_mul = a.mul(&b);
		let test_chip_add = TestCircuit::new(a.clone(), Some(b.clone()), Gadgets::Add);
		let test_chip_mul = TestCircuit::new(a, Some(b), Gadgets::Mul);

		let k = 5;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins_add = res_add.result.limbs;
		let pub_ins_mul = res_mul.result.limbs;
		let res =
			prove_and_verify::<Bn256, _, _>(params.clone(), test_chip_add, &[&pub_ins_add], rng)
				.unwrap();
		assert!(res);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip_mul, &[&pub_ins_mul], rng).unwrap();
		assert!(res);
	}

	#[test]
	fn should_sub_two_numbers() {
		// Testing sub with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("121231231231231231231231231233").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let res = a.sub(&b);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), Gadgets::Sub);
		let k = 5;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_div_two_numbers() {
		// Testing div with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("2").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let res = a.div(&b);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), Gadgets::Div);
		let k = 5;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
