/// Native implementation for the non-native field arithmetic
pub mod native;
/// RNS operations for the non-native field arithmetic
use self::native::Integer;
use crate::{
	params::rns::RnsParams, Chip, Chipset, CommonConfig, FieldExt, RegionCtx, UnassignedValue,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use native::{Quotient, ReductionWitness};
use std::marker::PhantomData;

/// UnassignedInteger struct
#[derive(Clone, Debug)]
pub struct UnassignedInteger<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Original value of the unassigned integer.
	pub(crate) integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// UnassignedInteger value limbs.
	pub(crate) limbs: [Value<N>; NUM_LIMBS],
	/// Phantom data for the Wrong Field.
	_wrong_field: PhantomData<W>,
	/// Phantom data for the RnsParams.
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new unassigned integer object
	pub fn new(
		integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, limbs: [Value<N>; NUM_LIMBS],
	) -> Self {
		Self { integer, limbs, _wrong_field: PhantomData, _rns: PhantomData }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	From<Integer<W, N, NUM_LIMBS, NUM_BITS, P>> for UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	fn from(int: Integer<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self {
			integer: Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::from_limbs(int.limbs),
			limbs: int.limbs.map(|x| Value::known(x)),
			_wrong_field: PhantomData,
			_rns: PhantomData,
		}
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> UnassignedValue
	for UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	fn without_witnesses() -> Self {
		Self {
			integer: Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::default(),
			limbs: [Value::unknown(); NUM_LIMBS],
			_wrong_field: PhantomData,
			_rns: PhantomData,
		}
	}
}

/// Assigns given values and their reduction witnesses
pub fn assign<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>(
	x: &[AssignedCell<N, N>; NUM_LIMBS], y_opt: Option<&[AssignedCell<N, N>; NUM_LIMBS]>,
	reduction_witness: &ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, common: &CommonConfig,
	ctx: &mut RegionCtx<N>,
) -> Result<AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>, Error>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	// Assign limbs
	for i in 0..NUM_LIMBS {
		ctx.copy_assign(common.advice[i], x[i].clone())?;
		if let Some(..) = y_opt {
			let y = y_opt.unwrap();
			ctx.copy_assign(common.advice[i + NUM_LIMBS], y[i].clone())?;
		}
	}

	// Assign intermediate values
	for i in 0..NUM_LIMBS {
		ctx.assign_advice(
			common.advice[i + 2 * NUM_LIMBS],
			Value::known(reduction_witness.intermediate[i]),
		)?;
	}

	// Assign result
	let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
		[(); NUM_LIMBS].map(|_| None);
	for i in 0..NUM_LIMBS {
		assigned_result[i] = Some(ctx.assign_advice(
			common.advice[i + 3 * NUM_LIMBS],
			Value::known(reduction_witness.result.limbs[i]),
		)?);
	}

	// Assign residues
	for i in 0..reduction_witness.residues.len() {
		ctx.assign_advice(
			common.advice[i + 4 * NUM_LIMBS],
			Value::known(reduction_witness.residues[i]),
		)?;
	}

	// Assign quotient
	match &reduction_witness.quotient {
		Quotient::Short(n) => {
			ctx.assign_advice(common.advice[5 * NUM_LIMBS - 1], Value::known(*n))?;
		},
		Quotient::Long(n) => {
			ctx.next();
			for i in 0..NUM_LIMBS {
				ctx.assign_advice(common.advice[i], Value::known(n.limbs[i]))?;
			}
		},
	}

	let assigned_result = AssignedInteger::new(
		reduction_witness.result.clone(),
		assigned_result.map(|x| x.unwrap()),
	);
	Ok(assigned_result)
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
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);

			for i in 0..NUM_LIMBS {
				let limbs_exp_i = v_cells.query_advice(common.advice[i], Rotation::cur());
				let t_exp_i =
					v_cells.query_advice(common.advice[i + 2 * NUM_LIMBS], Rotation::cur());
				let result_exp_i =
					v_cells.query_advice(common.advice[i + 3 * NUM_LIMBS], Rotation::cur());

				limbs_exp[i] = Some(limbs_exp_i);
				t_exp[i] = Some(t_exp_i);
				result_exp[i] = Some(result_exp_i);
			}

			let t_exp = t_exp.map(|x| x.unwrap());
			let limbs_exp = limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			let mut residues_exp = Vec::new();
			for i in 0..NUM_LIMBS / 2 {
				let res_exp_i =
					v_cells.query_advice(common.advice[i + 4 * NUM_LIMBS], Rotation::cur());
				residues_exp.push(res_exp_i);
			}

			let reduce_q_exp =
				v_cells.query_advice(common.advice[5 * NUM_LIMBS - 1], Rotation::cur());

			let s = v_cells.query_selector(selector);

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
				ctx.enable(*selector)?;
				assign(
					&self.assigned_integer.limbs, None, &reduction_witness, common, &mut ctx,
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
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("add", |v_cells| {
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);

			for i in 0..NUM_LIMBS {
				let x_exp_i = v_cells.query_advice(common.advice[i], Rotation::cur());
				let y_exp_i = v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur());
				let t_exp_i =
					v_cells.query_advice(common.advice[i + 2 * NUM_LIMBS], Rotation::cur());
				let result_exp_i =
					v_cells.query_advice(common.advice[i + 3 * NUM_LIMBS], Rotation::cur());

				x_limbs_exp[i] = Some(x_exp_i);
				y_limbs_exp[i] = Some(y_exp_i);
				t_exp[i] = Some(t_exp_i);
				result_exp[i] = Some(result_exp_i);
			}

			let t_exp = t_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			let mut residues_exp = Vec::new();
			for i in 0..NUM_LIMBS / 2 {
				let residue =
					v_cells.query_advice(common.advice[i + 4 * NUM_LIMBS], Rotation::cur());
				residues_exp.push(residue);
			}

			let add_q_exp = v_cells.query_advice(common.advice[5 * NUM_LIMBS - 1], Rotation::cur());

			let s = v_cells.query_selector(selector);

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exp.clone(), residues_exp);
			// NATIVE CONSTRAINTS
			let native_constraint = P::compose_exp(x_limbs_exp) + P::compose_exp(y_limbs_exp)
				- add_q_exp * p_in_n
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
				ctx.enable(*selector)?;
				assign(
					&self.x.limbs,
					Some(&self.y.limbs),
					&reduction_witness,
					common,
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
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);

			for i in 0..NUM_LIMBS {
				let x_exp_i = v_cells.query_advice(common.advice[i], Rotation::cur());
				let y_exp_i = v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur());
				let t_exp_i =
					v_cells.query_advice(common.advice[i + 2 * NUM_LIMBS], Rotation::cur());
				let result_exp_i =
					v_cells.query_advice(common.advice[i + 3 * NUM_LIMBS], Rotation::cur());

				x_limbs_exp[i] = Some(x_exp_i);
				y_limbs_exp[i] = Some(y_exp_i);
				t_exp[i] = Some(t_exp_i);
				result_exp[i] = Some(result_exp_i);
			}

			let t_exp = t_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			let mut residues_exp = Vec::new();
			for i in 0..NUM_LIMBS / 2 {
				residues_exp
					.push(v_cells.query_advice(common.advice[i + 4 * NUM_LIMBS], Rotation::cur()));
			}

			let sub_q_exp = v_cells.query_advice(common.advice[5 * NUM_LIMBS - 1], Rotation::cur());

			let s = v_cells.query_selector(selector);

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
				ctx.enable(*selector)?;
				assign(
					&self.x.limbs,
					Some(&self.y.limbs),
					&reduction_witness,
					common,
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
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut mul_q_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);

			for i in 0..NUM_LIMBS {
				let x_exp_i = v_cells.query_advice(common.advice[i], Rotation::cur());
				let y_exp_i = v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur());
				let t_exp_i =
					v_cells.query_advice(common.advice[i + 2 * NUM_LIMBS], Rotation::cur());
				let result_exp_i =
					v_cells.query_advice(common.advice[i + 3 * NUM_LIMBS], Rotation::cur());
				let q_exp_i = v_cells.query_advice(common.advice[i], Rotation::next());

				x_limbs_exp[i] = Some(x_exp_i);
				y_limbs_exp[i] = Some(y_exp_i);
				t_exp[i] = Some(t_exp_i);
				result_exp[i] = Some(result_exp_i);
				mul_q_exp[i] = Some(q_exp_i);
			}

			let t_exp = t_exp.map(|x| x.unwrap());
			let mul_q_exp = mul_q_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			let mut residues_exp = Vec::new();
			for i in 0..NUM_LIMBS / 2 {
				let res_exp_i =
					v_cells.query_advice(common.advice[i + 4 * NUM_LIMBS], Rotation::cur());
				residues_exp.push(res_exp_i);
			}

			let s = v_cells.query_selector(selector);

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
				ctx.enable(*selector)?;
				assign(
					&self.x.limbs,
					Some(&self.y.limbs),
					&reduction_witness,
					common,
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
			let mut t_exp = [(); NUM_LIMBS].map(|_| None);
			let mut div_q_exp = [(); NUM_LIMBS].map(|_| None);
			let mut x_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut y_limbs_exp = [(); NUM_LIMBS].map(|_| None);
			let mut result_exp = [(); NUM_LIMBS].map(|_| None);

			for i in 0..NUM_LIMBS {
				let x_exp_i = v_cells.query_advice(common.advice[i], Rotation::cur());
				let y_exp_i = v_cells.query_advice(common.advice[i + NUM_LIMBS], Rotation::cur());
				let t_exp_i =
					v_cells.query_advice(common.advice[i + 2 * NUM_LIMBS], Rotation::cur());
				let result_exp_i =
					v_cells.query_advice(common.advice[i + 3 * NUM_LIMBS], Rotation::cur());
				let q_exp_i = v_cells.query_advice(common.advice[i], Rotation::next());

				x_limbs_exp[i] = Some(x_exp_i);
				y_limbs_exp[i] = Some(y_exp_i);
				t_exp[i] = Some(t_exp_i);
				result_exp[i] = Some(result_exp_i);
				div_q_exp[i] = Some(q_exp_i);
			}

			let t_exp = t_exp.map(|x| x.unwrap());
			let div_q_exp = div_q_exp.map(|x| x.unwrap());
			let x_limbs_exp = x_limbs_exp.map(|x| x.unwrap());
			let y_limbs_exp = y_limbs_exp.map(|x| x.unwrap());
			let result_exp = result_exp.map(|x| x.unwrap());

			let mut residues_exp = Vec::new();
			for i in 0..NUM_LIMBS / 2 {
				let res_exp_i =
					v_cells.query_advice(common.advice[i + 4 * NUM_LIMBS], Rotation::cur());
				residues_exp.push(res_exp_i);
			}

			let s = v_cells.query_selector(selector);

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
				ctx.enable(*selector)?;
				assign(
					&self.x.limbs,
					Some(&self.y.limbs),
					&reduction_witness,
					common,
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
	pub(crate) limbs: [AssignedCell<N, N>; NUM_LIMBS],
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a new `AssignedInteger` given its values
	pub fn new(
		integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, limbs: [AssignedCell<N, N>; NUM_LIMBS],
	) -> Self {
		Self { integer, limbs }
	}
}

/// Integer assigner chip
pub struct IntegerAssigner<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerAssigner<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Constructor for Integer assigner
	pub fn new(x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { x }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<N>
	for IntegerAssigner<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Config = ();
	type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

	fn synthesize(
		self, common: &CommonConfig, _: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let assigned_limbs = layouter.assign_region(
			|| "int_assigner",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				let mut limbs = Vec::new();
				for i in 0..NUM_LIMBS {
					let assigned_limb = ctx.assign_advice(common.advice[i], self.x.limbs[i])?;
					limbs.push(assigned_limb);
				}

				Ok(limbs)
			},
		)?;

		let x_assigned = AssignedInteger::new(self.x.integer, assigned_limbs.try_into().unwrap());
		Ok(x_assigned)
	}
}

#[cfg(test)]
mod test {
	use super::{native::Integer, *};
	use crate::{params::rns::bn256::Bn256_4_68, Chipset, CommonConfig, UnassignedValue};
	use halo2::{
		circuit::SimpleFloorPlanner,
		dev::MockProver,
		halo2curves::bn256::{Fq, Fr},
		plonk::Circuit,
	};
	use num_bigint::BigUint;

	use std::str::FromStr;

	type W = Fq;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Bn256_4_68;

	#[derive(Clone, Debug)]
	struct TestConfig {
		common: CommonConfig,
		reduce_selector: Selector,
		add_selector: Selector,
		sub_selector: Selector,
		mul_selector: Selector,
		div_selector: Selector,
	}

	impl TestConfig {
		pub fn new(meta: &mut ConstraintSystem<N>) -> Self {
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

			Self { common, reduce_selector, add_selector, sub_selector, mul_selector, div_selector }
		}
	}

	struct SingleAssigner {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl SingleAssigner {
		fn new(x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
			Self { x }
		}
	}

	impl Chipset<N> for SingleAssigner {
		type Config = ();
		type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

		fn synthesize(
			self, common: &CommonConfig, _c: &Self::Config, mut layouter: impl Layouter<N>,
		) -> Result<Self::Output, Error> {
			let x_limbs_assigned = layouter.assign_region(
				|| "temp",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_advice(common.advice[i], self.x.limbs[i])?;
						x_limbs[i] = Some(x);
					}
					Ok(x_limbs)
				},
			)?;

			let x =
				AssignedInteger::new(self.x.integer.clone(), x_limbs_assigned.map(|x| x.unwrap()));
			Ok(x)
		}
	}

	struct ToupleAssigner {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl ToupleAssigner {
		fn new(
			x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
			y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self { x, y }
		}
	}

	impl Chipset<N> for ToupleAssigner {
		type Config = ();
		type Output = (
			AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
			AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		);

		fn synthesize(
			self, common: &CommonConfig, _c: &Self::Config, mut layouter: impl Layouter<N>,
		) -> Result<Self::Output, Error> {
			let (x_limbs_assigned, y_limbs_assigned) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_advice(common.advice[i], self.x.limbs[i])?;
						x_limbs[i] = Some(x);
					}
					ctx.next();

					let mut y_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let y = ctx.assign_advice(common.advice[i], self.y.limbs[i])?;
						y_limbs[i] = Some(y);
					}
					Ok((x_limbs, y_limbs))
				},
			)?;

			let x =
				AssignedInteger::new(self.x.integer.clone(), x_limbs_assigned.map(|x| x.unwrap()));
			let y =
				AssignedInteger::new(self.y.integer.clone(), y_limbs_assigned.map(|x| x.unwrap()));
			Ok((x, y))
		}
	}

	#[derive(Clone)]
	struct ReduceTestCircuit {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl ReduceTestCircuit {
		fn new(x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
			Self { x: UnassignedInteger::from(x) }
		}
	}

	impl Circuit<N> for ReduceTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: UnassignedInteger::without_witnesses() }
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let single_assigner = SingleAssigner::new(self.x.clone());
			let x_assigned = single_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "assign x"),
			)?;

			let chip = IntegerReduceChip::new(x_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.reduce_selector,
				layouter.namespace(|| "reduce"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.limbs[i].cell(), config.common.instance, i)?;
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
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let res = a.reduce();
		let test_chip = ReduceTestCircuit::new(a);

		let k = 4;
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
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let res = a.reduce();
		let test_chip = ReduceTestCircuit::new(a);

		let k = 4;
		let p_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct AddTestCircuit {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl AddTestCircuit {
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self { x: UnassignedInteger::from(x), y: UnassignedInteger::from(y) }
		}
	}

	impl Circuit<N> for AddTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				x: UnassignedInteger::without_witnesses(),
				y: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let touple_assigner = ToupleAssigner::new(self.x.clone(), self.y.clone());
			let (x_assigned, y_assigned) = touple_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "assign x and y"),
			)?;

			let chip = IntegerAddChip::new(x_assigned, y_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.add_selector,
				layouter.namespace(|| "add"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.limbs[i].cell(), config.common.instance, i)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_add_two_numbers() {
		// Testing add with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("3534512312312312314235346475676435").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let res = a.add(&b);
		let test_chip = AddTestCircuit::new(a, b);

		let k = 4;
		let p_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct SubTestCircuit {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl SubTestCircuit {
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self { x: UnassignedInteger::from(x), y: UnassignedInteger::from(y) }
		}
	}

	impl Circuit<N> for SubTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				x: UnassignedInteger::without_witnesses(),
				y: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let touple_assigner = ToupleAssigner::new(self.x.clone(), self.y.clone());
			let (x_assigned, y_assigned) = touple_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "assign x and y"),
			)?;

			let chip = IntegerSubChip::new(x_assigned, y_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.sub_selector,
				layouter.namespace(|| "sub"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.limbs[i].cell(), config.common.instance, i)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_sub_two_numbers() {
		// Testing sub with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("121231231231231231231231231233").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let res = a.sub(&b);
		let test_chip = SubTestCircuit::new(a, b);
		let k = 4;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct MulTestCircuit {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl MulTestCircuit {
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self { x: UnassignedInteger::from(x), y: UnassignedInteger::from(y) }
		}
	}

	impl Circuit<N> for MulTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				x: UnassignedInteger::without_witnesses(),
				y: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let touple_assigner = ToupleAssigner::new(self.x.clone(), self.y.clone());
			let (x_assigned, y_assigned) = touple_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "assign x and y"),
			)?;

			let chip = IntegerMulChip::new(x_assigned, y_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.mul_selector,
				layouter.namespace(|| "mul"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.limbs[i].cell(), config.common.instance, i)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_mul_two_numbers() {
		// Testing mul with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("121231231231231231231231231233").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let res = a.mul(&b);
		let test_chip = MulTestCircuit::new(a, b);
		let k = 4;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct DivTestCircuit {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl DivTestCircuit {
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self { x: UnassignedInteger::from(x), y: UnassignedInteger::from(y) }
		}
	}

	impl Circuit<N> for DivTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				x: UnassignedInteger::without_witnesses(),
				y: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let touple_assigner = ToupleAssigner::new(self.x.clone(), self.y.clone());
			let (x_assigned, y_assigned) = touple_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "assign x and y"),
			)?;

			let chip = IntegerDivChip::new(x_assigned, y_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.div_selector,
				layouter.namespace(|| "div"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.limbs[i].cell(), config.common.instance, i)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_div_two_numbers() {
		// Testing div with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str("2").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let res = a.div(&b);
		let test_chip = DivTestCircuit::new(a, b);
		let k = 4;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
