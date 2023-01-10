/// Native implementation for the non-native field arithmetic
pub mod native;
/// RNS operations for the non-native field arithmetic
pub mod rns;

use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use native::{Quotient, ReductionWitness};
use rns::RnsParams;
use std::marker::PhantomData;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct IntegerConfig<const NUM_LIMBS: usize> {
	/// Configures columns for the x limbs.
	pub(crate) x_limbs: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the y limbs.
	pub(crate) y_limbs: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the quotient value(s).
	pub(crate) quotient: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the intermediate values.
	pub(crate) intermediate: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the residues.
	pub(crate) residues: Vec<Column<Advice>>,
	/// Configures a fixed boolean value for each row of the circuit.
	pub(crate) reduce_selector: Selector,
	/// Configures a fixed boolean value for each row of the circuit.
	pub(crate) add_selector: Selector,
	/// Configures a fixed boolean value for each row of the circuit.
	pub(crate) sub_selector: Selector,
	/// Configures a fixed boolean value for each row of the circuit.
	pub(crate) mul_selector: Selector,
	/// Configures a fixed boolean value for each row of the circuit.
	pub(crate) div_selector: Selector,
}

/// Constructs a chip for the circuit.
pub struct IntegerChip<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	IntegerChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<N>) -> IntegerConfig<NUM_LIMBS> {
		let x_limbs = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let y_limbs = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let quotient = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let intermediate = [(); NUM_LIMBS].map(|_| meta.advice_column());
		let residues: Vec<Column<Advice>> =
			vec![(); NUM_LIMBS / 2].iter().map(|_| meta.advice_column()).collect();
		let reduce_selector = meta.selector();
		let add_selector = meta.selector();
		let sub_selector = meta.selector();
		let mul_selector = meta.selector();
		let div_selector = meta.selector();

		x_limbs.map(|x| meta.enable_equality(x));
		y_limbs.map(|y| meta.enable_equality(y));

		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("reduce", |v_cells| {
			let reduce_s = v_cells.query_selector(reduce_selector);
			let y_limb_exps = y_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let reduce_q_exp = v_cells.query_advice(quotient[0], Rotation::cur());
			let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exps.clone(), residues_exps);
			// NATIVE CONSTRAINTS
			let native_constraint =
				P::compose_exp(y_limb_exps) - reduce_q_exp * p_in_n - P::compose_exp(result_exps);
			constraints.push(native_constraint);

			constraints.iter().map(|x| reduce_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		meta.create_gate("add", |v_cells| {
			let add_s = v_cells.query_selector(add_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exps.clone(), residues_exps);
			// NATIVE CONSTRAINTS
			let native_constraint = P::compose_exp(x_limb_exps) + P::compose_exp(y_limb_exps)
				- P::compose_exp(result_exps);
			constraints.push(native_constraint);

			constraints.iter().map(|x| add_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		meta.create_gate("sub", |v_cells| {
			let sub_s = v_cells.query_selector(sub_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let sub_q_exp = v_cells.query_advice(quotient[0], Rotation::cur());
			let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exps.clone(), residues_exps);
			// NATIVE CONSTRAINTS
			let native_constraint = P::compose_exp(x_limb_exps) - P::compose_exp(y_limb_exps)
				+ sub_q_exp * p_in_n
				- P::compose_exp(result_exps);
			constraints.push(native_constraint);

			constraints.iter().map(|x| sub_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		meta.create_gate("mul", |v_cells| {
			let mul_s = v_cells.query_selector(mul_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let mul_q_exp = quotient.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exps.clone(), residues_exps);
			// NATIVE CONSTRAINTS
			let native_constraints = P::compose_exp(x_limb_exps) * P::compose_exp(y_limb_exps)
				- P::compose_exp(mul_q_exp) * p_in_n
				- P::compose_exp(result_exps);
			constraints.push(native_constraints);

			constraints.iter().map(|x| mul_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		meta.create_gate("div", |v_cells| {
			let div_s = v_cells.query_selector(div_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let div_q_exp = quotient.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let t_exp = intermediate.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let result_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::next()));
			let residues_exps: Vec<Expression<N>> =
				residues.iter().map(|x| v_cells.query_advice(*x, Rotation::cur())).collect();

			// REDUCTION CONSTRAINTS
			let mut constraints =
				P::constrain_binary_crt_exp(t_exp, result_exps.clone(), residues_exps);
			//NATIVE CONSTRAINTS
			let native_constraints = P::compose_exp(y_limb_exps) * P::compose_exp(result_exps)
				- P::compose_exp(x_limb_exps)
				- P::compose_exp(div_q_exp) * p_in_n;
			constraints.push(native_constraints);

			constraints.iter().map(|x| div_s.clone() * x.clone()).collect::<Vec<Expression<N>>>()
		});

		IntegerConfig {
			x_limbs,
			y_limbs,
			quotient,
			intermediate,
			residues,
			reduce_selector,
			add_selector,
			sub_selector,
			mul_selector,
			div_selector,
		}
	}

	/// Assigns given values and their reduction witnesses
	pub fn assign(
		x_opt: Option<&[AssignedCell<N, N>; NUM_LIMBS]>, y: &[AssignedCell<N, N>; NUM_LIMBS],
		reduction_witness: &ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		config: &IntegerConfig<NUM_LIMBS>, region: &mut Region<'_, N>, row: usize,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		match &reduction_witness.quotient {
			Quotient::Short(n) => {
				region.assign_advice(
					|| "quotient",
					config.quotient[0],
					row,
					|| Value::known(*n),
				)?;
			},
			Quotient::Long(n) => {
				for i in 0..NUM_LIMBS {
					region.assign_advice(
						|| format!("quotient_{}", i),
						config.quotient[i],
						row,
						|| Value::known(n.limbs[i]),
					)?;
				}
			},
		}

		for i in 0..NUM_LIMBS {
			if x_opt.is_some() {
				let x = x_opt.unwrap();
				x[i].copy_advice(|| format!("limb_x_{}", i), region, config.x_limbs[i], row)?;
			}
			y[i].copy_advice(|| format!("limb_y_{}", i), region, config.y_limbs[i], row)?;

			region.assign_advice(
				|| format!("intermediates_{}", i),
				config.intermediate[i],
				row,
				|| Value::known(reduction_witness.intermediate[i]),
			)?;
		}

		for i in 0..reduction_witness.residues.len() {
			region.assign_advice(
				|| format!("residues_{}", i),
				config.residues[i],
				row,
				|| Value::known(reduction_witness.residues[i]),
			)?;
		}

		let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			assigned_result[i] = Some(region.assign_advice(
				|| format!("result_{}", i),
				config.x_limbs[i],
				row + 1,
				|| Value::known(reduction_witness.result.limbs[i]),
			)?)
		}
		let assigned_result = assigned_result.map(|x| x.unwrap());
		Ok(assigned_result)
	}

	/// Assign cells for reduce operation.
	pub fn reduce(
		limbs: [AssignedCell<N, N>; NUM_LIMBS], rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		config: IntegerConfig<NUM_LIMBS>, mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "reduce_operation",
			|mut region: Region<'_, N>| {
				config.reduce_selector.enable(&mut region, 0)?;
				Self::assign(None, &limbs, &rw, &config, &mut region, 0)
			},
		)
	}

	/// Assign cells for add operation.
	pub fn add(
		x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "add_operation",
			|mut region: Region<'_, N>| {
				config.add_selector.enable(&mut region, 0)?;
				Self::assign(Some(&x_limbs), &y_limbs, &rw, &config, &mut region, 0)
			},
		)
	}

	/// Assign cells for mul operation.
	pub fn mul(
		x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "mul_operation",
			|mut region: Region<'_, N>| {
				config.mul_selector.enable(&mut region, 0)?;
				Self::assign(Some(&x_limbs), &y_limbs, &rw, &config, &mut region, 0)
			},
		)
	}

	/// Assign cells for sub operation.
	pub fn sub(
		x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "sub_operation",
			|mut region: Region<'_, N>| {
				config.sub_selector.enable(&mut region, 0)?;
				Self::assign(Some(&x_limbs), &y_limbs, &rw, &config, &mut region, 0)
			},
		)
	}

	/// Assign cells for div operation.
	pub fn div(
		x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "div_operation",
			|mut region: Region<'_, N>| {
				config.div_selector.enable(&mut region, 0)?;
				Self::assign(Some(&x_limbs), &y_limbs, &rw, &config, &mut region, 0)
			},
		)
	}
}

#[derive(Debug, Clone)]
///Assigned Integer
pub struct AssignedInteger<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) integer: [AssignedCell<N, N>; NUM_LIMBS],
	pub(crate) rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a new `AssignedInteger` given its values
	pub fn new(
		integer: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { integer, rw }
	}
}

#[cfg(test)]
mod test {
	use super::{native::Integer, rns::Bn256_4_68, *};
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fq, Fr},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};
	use num_bigint::BigUint;
	use std::str::FromStr;

	#[derive(Clone)]
	enum Gadgets {
		Reduce,
		Add,
		Mul,
		Sub,
		Div,
	}

	#[derive(Clone, Debug)]
	struct TestConfig<const NUM_LIMBS: usize> {
		integer: IntegerConfig<NUM_LIMBS>,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: Option<Integer<W, N, NUM_LIMBS, NUM_BITS, P>>,
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		gadget: Gadgets,
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
		TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		fn new(
			x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
			y: Option<Integer<W, N, NUM_LIMBS, NUM_BITS, P>>,
			rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, gadget: Gadgets,
		) -> Self {
			Self { x, y, rw, gadget }
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
			let integer = IntegerChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(instance);

			TestConfig { integer, temp, pub_ins: instance }
		}

		fn synthesize(
			&self, config: TestConfig<NUM_LIMBS>, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let (x_limbs_assigned, y_limbs_assigned) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, N>| {
					let mut x_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut y_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = region.assign_advice(
							|| "temp_x",
							config.temp,
							i,
							|| Value::known(self.x.limbs[i]),
						)?;
						x_limbs[i] = Some(x);

						if self.y.is_some() {
							let y_unwrapped = self.y.clone().unwrap();
							let y = region.assign_advice(
								|| "temp_y",
								config.temp,
								i + NUM_LIMBS,
								|| Value::known(y_unwrapped.limbs[i]),
							)?;
							y_limbs[i] = Some(y);
						}
					}
					Ok((x_limbs, y_limbs))
				},
			)?;

			let res = match self.gadget {
				Gadgets::Reduce => IntegerChip::reduce(
					x_limbs_assigned.map(|x| x.unwrap()),
					self.rw.clone(),
					config.integer.clone(),
					layouter.namespace(|| "reduce"),
				)?,

				Gadgets::Add => IntegerChip::add(
					x_limbs_assigned.map(|x| x.unwrap()),
					y_limbs_assigned.map(|y| y.unwrap()),
					self.rw.clone(),
					config.integer.clone(),
					layouter.namespace(|| "add"),
				)?,
				Gadgets::Mul => IntegerChip::mul(
					x_limbs_assigned.map(|x| x.unwrap()),
					y_limbs_assigned.map(|y| y.unwrap()),
					self.rw.clone(),
					config.integer.clone(),
					layouter.namespace(|| "mul"),
				)?,
				Gadgets::Sub => IntegerChip::sub(
					x_limbs_assigned.map(|x| x.unwrap()),
					y_limbs_assigned.map(|y| y.unwrap()),
					self.rw.clone(),
					config.integer.clone(),
					layouter.namespace(|| "sub"),
				)?,
				Gadgets::Div => IntegerChip::div(
					x_limbs_assigned.map(|x| x.unwrap()),
					y_limbs_assigned.map(|y| y.unwrap()),
					self.rw.clone(),
					config.integer.clone(),
					layouter.namespace(|| "div"),
				)?,
			};

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(res[i].cell(), config.pub_ins, i)?;
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
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			a.clone(),
			None,
			res.clone(),
			Gadgets::Reduce,
		);

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
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let res = a.reduce();
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			a.clone(),
			None,
			res.clone(),
			Gadgets::Reduce,
		);

		let k = 4;
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
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), res.clone(), Gadgets::Add);

		let k = 4;
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
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), res.clone(), Gadgets::Mul);
		let k = 4;
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
		let test_chip_add =
			TestCircuit::new(a.clone(), Some(b.clone()), res_add.clone(), Gadgets::Add);
		let test_chip_mul = TestCircuit::new(a, Some(b), res_mul.clone(), Gadgets::Mul);

		let k = 4;
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
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), res.clone(), Gadgets::Sub);
		let k = 4;
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
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a, Some(b), res.clone(), Gadgets::Div);
		let k = 4;
		let pub_ins = res.result.limbs.to_vec();
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
