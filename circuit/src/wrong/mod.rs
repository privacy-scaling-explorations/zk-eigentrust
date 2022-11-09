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
use native::ReductionWitness;
use rns::RnsParams;
use std::marker::PhantomData;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
struct IntegerConfig<const NUM_LIMBS: usize> {
	/// Configures columns for the x limbs.
	x_limbs: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the y limbs.
	y_limbs: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the quotient value(s).
	quotient: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the intermediate values.
	intermediate: [Column<Advice>; NUM_LIMBS],
	/// Configures columns for the residues.
	residues: Vec<Column<Advice>>,
	/// Configures a fixed boolean value for each row of the circuit.
	add_selector: Selector,
	/// Configures a fixed boolean value for each row of the circuit.
	mul_selector: Selector,
}

/// Constructs a chip for the circuit.
struct IntegerChip<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
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
		let add_selector = meta.selector();
		let mul_selector = meta.selector();

		x_limbs.map(|x| meta.enable_equality(x));
		y_limbs.map(|y| meta.enable_equality(y));

		let p_prime = P::negative_wrong_modulus_decomposed();
		let p_in_n = P::wrong_modulus_in_native_modulus();

		meta.create_gate("add", |v_cells| {
			let add_s = v_cells.query_selector(add_selector);
			let x_limb_exps = x_limbs.map(|x| v_cells.query_advice(x, Rotation::cur()));
			let y_limb_exps = y_limbs.map(|y| v_cells.query_advice(y, Rotation::cur()));
			let add_q_exp = v_cells.query_advice(quotient[0], Rotation::cur());
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
		x_limbs: [AssignedCell<N, N>; NUM_LIMBS], y_limbs: [AssignedCell<N, N>; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, config: IntegerConfig<NUM_LIMBS>,
		mut layouter: impl Layouter<N>,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		layouter.assign_region(
			|| "add_operation",
			|mut region: Region<'_, N>| {
				config.add_selector.enable(&mut region, 0)?;

				region.assign_advice(
					|| "quotient",
					config.quotient[0],
					0,
					|| Value::known(rw.quotient.clone().add().unwrap()),
				)?;

				for i in 0..NUM_LIMBS {
					x_limbs[i].copy_advice(
						|| format!("x_limb_{}", i),
						&mut region,
						config.x_limbs[i],
						0,
					)?;

					y_limbs[i].copy_advice(
						|| format!("y_limb_{}", i),
						&mut region,
						config.y_limbs[i],
						0,
					)?;

					region.assign_advice(
						|| format!("intermediate_{}", i),
						config.intermediate[i],
						0,
						|| Value::known(rw.intermediate[i]),
					)?;
				}

				for i in 0..rw.residues.len() {
					region.assign_advice(
						|| format!("residues_{}", i),
						config.residues[i],
						0,
						|| Value::known(rw.residues[i]),
					)?;
				}

				let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[(); NUM_LIMBS].map(|_| None);
				for i in 0..NUM_LIMBS {
					assigned_result[i] = Some(region.assign_advice(
						|| format!("result_{}", i),
						config.x_limbs[i],
						1,
						|| Value::known(rw.result.limbs[i]),
					)?)
				}

				let assigned_result = assigned_result.map(|x| x.unwrap());

				Ok(assigned_result)
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

				for i in 0..NUM_LIMBS {
					x_limbs[i].copy_advice(
						|| format!("x_limb_{}", i),
						&mut region,
						config.x_limbs[i],
						0,
					)?;

					y_limbs[i].copy_advice(
						|| format!("y_limb_{}", i),
						&mut region,
						config.y_limbs[i],
						0,
					)?;

					region.assign_advice(
						|| format!("quotient_{}", i),
						config.quotient[i],
						0,
						|| Value::known(rw.quotient.clone().mul().unwrap().limbs[i]),
					)?;

					region.assign_advice(
						|| format!("intermediate_{}", i),
						config.intermediate[i],
						0,
						|| Value::known(rw.intermediate[i]),
					)?;
				}

				for i in 0..rw.residues.len() {
					region.assign_advice(
						|| format!("residues_{}", i),
						config.residues[i],
						0,
						|| Value::known(rw.residues[i]),
					)?;
				}

				let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[(); NUM_LIMBS].map(|_| None);
				for i in 0..NUM_LIMBS {
					assigned_result[i] = Some(region.assign_advice(
						|| format!("result_{}", i),
						config.x_limbs[i],
						1,
						|| Value::known(rw.result.limbs[i]),
					)?);
				}

				let assigned_result = assigned_result.map(|x| x.unwrap());

				Ok(assigned_result)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::{native::Integer, rns::Bn256_4_68, *};
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Fq, Fr},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::Circuit,
		},
	};
	use num_bigint::BigUint;
	use num_traits::{One, Zero};
	use std::str::FromStr;

	#[derive(Clone)]
	enum Gadgets {
		Add,
		Mul,
	}

	#[derive(Clone, Debug)]
	struct TestConfig<const NUM_LIMBS: usize> {
		integer: IntegerConfig<NUM_LIMBS>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		x_limbs: [N; NUM_LIMBS],
		y_limbs: [N; NUM_LIMBS],
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		gadget: Gadgets,
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
		TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		fn new(
			x_limbs: [N; NUM_LIMBS], y_limbs: [N; NUM_LIMBS],
			rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, gadget: Gadgets,
		) -> Self {
			Self { x_limbs, y_limbs, rw, gadget }
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

			meta.enable_equality(temp);

			TestConfig { integer, temp }
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
							|| Value::known(self.x_limbs[i]),
						)?;
						let y = region.assign_advice(
							|| "temp_y",
							config.temp,
							i + NUM_LIMBS,
							|| Value::known(self.y_limbs[i]),
						)?;

						x_limbs[i] = Some(x);
						y_limbs[i] = Some(y);
					}

					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|y| y.unwrap())))
				},
			)?;

			match self.gadget {
				Gadgets::Add => {
					let _ = IntegerChip::add(
						x_limbs_assigned,
						y_limbs_assigned,
						self.rw.clone(),
						config.integer,
						layouter.namespace(|| "add"),
					)?;
				},
				Gadgets::Mul => {
					let _ = IntegerChip::mul(
						x_limbs_assigned,
						y_limbs_assigned,
						self.rw.clone(),
						config.integer,
						layouter.namespace(|| "mul"),
					)?;
				},
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
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.add(&b);
		let test_chip =
			TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.limbs, b.limbs, c, Gadgets::Add);

		let k = 10;
		let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_add_accumulate_array_of_numbers() {
		// Testing add with array of 8 elements.
		let a_big = BigUint::from_str("4057452572750886963137894").unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::zero());
		let mut acc = carry.add(&carry);
		for i in 0..a_big_array.len() {
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			let b = acc.result;
			acc = a.add(&b);
			let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
				a.limbs,
				b.limbs,
				acc.clone(),
				Gadgets::Add,
			);
			let k = 10;
			let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
			assert_eq!(prover.verify(), Ok(()));
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
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.mul(&b);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			a.limbs,
			b.limbs,
			c.clone(),
			Gadgets::Mul,
		);
		let k = 10;
		let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_accumulate_array_of_numbers() {
		// Testing mul with array of 8 elements.
		let a_big = BigUint::from_str("4057452572750886963137894").unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::one());
		let mut acc = carry.add(&carry);
		for i in 0..a_big_array.len() {
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			let b = acc.result;
			acc = a.mul(&b);
			let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
				a.limbs,
				b.limbs,
				acc.clone(),
				Gadgets::Mul,
			);
			let k = 10;
			let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
			assert_eq!(prover.verify(), Ok(()));
		}
	}
}
