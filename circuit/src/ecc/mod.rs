/// Native version of the chip
pub mod native;

use std::marker::PhantomData;

use crate::{
	gadgets::bits2num::{Bits2NumChip, Bits2NumConfig},
	integer::{native::ReductionWitness, rns::RnsParams, IntegerChip, IntegerConfig},
};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

use self::native::EcPoint;

#[derive(Debug, Clone)]
struct EccConfig<const NUM_LIMBS: usize> {
	bits2num: Bits2NumConfig,
	integer: IntegerConfig<NUM_LIMBS>,
	selectors: [Selector; 11],
}

struct EccChip<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Assigns given values and their reduction witnesses
	fn wrapper(
		name: &str, x: &[AssignedCell<N, N>; NUM_LIMBS], y: &[AssignedCell<N, N>; NUM_LIMBS],
		reduction_witnesses: &ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>, quotient: &str,
		config: &EccConfig<NUM_LIMBS>, region: &mut Region<'_, N>, round: usize,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		config.selectors[round].enable(region, round)?;

		if quotient == "add" {
			region.assign_advice(
				|| format!("{name}_quotient"),
				config.integer.quotient[0],
				round,
				|| Value::known(reduction_witnesses.quotient.clone().add().unwrap()),
			)?;
		} else if quotient == "mul" {
			for i in 0..NUM_LIMBS {
				region.assign_advice(
					|| format!("{name}_quotient_{}", i),
					config.integer.quotient[i],
					round,
					|| Value::known(reduction_witnesses.quotient.clone().mul().unwrap().limbs[i]),
				)?;
			}
		}

		for i in 0..NUM_LIMBS {
			x[i].copy_advice(
				|| format!("{name}_{}", i),
				region,
				config.integer.x_limbs[i],
				round,
			)?;
			y[i].copy_advice(
				|| format!("{name}_{}", i),
				region,
				config.integer.y_limbs[i],
				round,
			)?;

			region.assign_advice(
				|| format!("{name}_intermediates_{}", i),
				config.integer.intermediate[i],
				round,
				|| Value::known(reduction_witnesses.intermediate[i]),
			)?;
		}

		for i in 0..reduction_witnesses.residues.len() {
			region.assign_advice(
				|| format!("{name}_residues_{}", i),
				config.integer.residues[i],
				round,
				|| Value::known(reduction_witnesses.residues[i]),
			)?;
		}

		let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			assigned_result[i] = Some(region.assign_advice(
				|| format!("{name}_result_{}", i),
				config.integer.x_limbs[i],
				round + 1,
				|| Value::known(reduction_witnesses.result.limbs[i]),
			)?)
		}
		let assigned_result = assigned_result.map(|x| x.unwrap());
		Ok(assigned_result)
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<N>) -> EccConfig<NUM_LIMBS> {
		const BITS: usize = 256;
		let bits2num = Bits2NumChip::<N, BITS>::configure(meta);
		let integer = IntegerChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(meta);
		let selectors = [(); 11].map(|_| meta.selector());

		EccConfig { bits2num, integer, selectors }
	}

	pub fn add(
		// Assigns a cell for the p_x.
		p_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the p_y.
		p_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for p -- make sure p is in the W field before being passed
		//p_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigns a cell for the q_x.
		q_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the q_y.
		q_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for `q` -- make sure `q` is in the W field before being passed
		//q_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for add operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc config columns
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// Assign a region where we use columns from Integer chip
		// sub selector - row 0
		// sub selector - row 1
		// div selector - row 2
		// mul selector - row 3
		// sub selector - row 4
		// sub selector - row 5
		// sub selector - row 6
		// mul selector - row 7
		// sub selector - row 8
		layouter.assign_region(
			|| "elliptic_add_operation",
			|mut region: Region<'_, N>| {
				//numerator = self.y.sub(&other.y)
				let numerator = Self::wrapper(
					"numerator", &p_y, &q_y, &reduction_witnesses[0], "add", &config, &mut region,
					0,
				)
				.unwrap();

				//denominator = self.x.sub(&other.x)
				let denominator = Self::wrapper(
					"denominator", &p_x, &q_x, &reduction_witnesses[1], "add", &config,
					&mut region, 1,
				)
				.unwrap();

				//m = numerator.result.div(&denominator.result)
				let m = Self::wrapper(
					"m", &numerator, &denominator, &reduction_witnesses[2], "mul", &config,
					&mut region, 2,
				)
				.unwrap();

				//m_squared = m.result.mul(&m.result)
				let m_squared = Self::wrapper(
					"m_squared", &m, &m, &reduction_witnesses[3], "mul", &config, &mut region, 3,
				)
				.unwrap();

				//m_squared_minus_p_x = m_squared.result.sub(&self.x)
				let m_squared_minus_p_x = Self::wrapper(
					"m_squared_minus_p_x", &m_squared, &p_x, &reduction_witnesses[4], "add",
					&config, &mut region, 4,
				)
				.unwrap();

				//r_x = m_squared_minus_p_x.result.sub(&other.x)
				let r_x = Self::wrapper(
					"r_x", &m_squared_minus_p_x, &q_x, &reduction_witnesses[5], "add", &config,
					&mut region, 5,
				)
				.unwrap();

				//r_x_minus_p_x = r_x.result.sub(&self.x)
				let r_x_minus_p_x = Self::wrapper(
					"r_x_minus_p_x", &m_squared_minus_p_x, &q_x, &reduction_witnesses[6], "add",
					&config, &mut region, 6,
				)
				.unwrap();

				//let m_times_r_x_minus_p_x = m.result.mul(&r_x_minus_p_x.result);
				let m_times_r_x_minus_p_x = Self::wrapper(
					"m_times_r_x_minus_p_x", &m, &r_x_minus_p_x, &reduction_witnesses[7], "mul",
					&config, &mut region, 7,
				)
				.unwrap();

				//r_y = m_times_r_x_minus_p_x.result.sub(&self.y)
				let r_y = Self::wrapper(
					"r_y", &m_times_r_x_minus_p_x, &p_y, &reduction_witnesses[8], "add", &config,
					&mut region, 8,
				)
				.unwrap();

				Ok((r_x, r_y))
			},
		)
	}

	pub fn double(
		// Assigns a cell for the p_x.
		p_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the p_y.
		p_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for p -- make sure p is in the W field before being passed
		//p_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for double operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc Config
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// add selector - row 0
		// mul selector - row 1
		// mul3 selector - row 2
		// div selector - row 3
		// add selector - row 4
		// mul selector - row 5
		// sub selector - row 6
		// sub selector - row 7
		// mul selector - row 8
		// sub selector - row 9
		layouter.assign_region(
			|| "elliptic_add_operation",
			|mut region: Region<'_, N>| {
				// double_p_y = self.y.add(&self.y)
				let double_p_y = Self::wrapper(
					"double_p_y", &p_y, &p_y, &reduction_witnesses[0], "add", &config, &mut region,
					0,
				)
				.unwrap();

				// p_x_square = self.x.mul(&self.x)
				let p_x_square = Self::wrapper(
					"p_x_square", &p_x, &p_x, &reduction_witnesses[1], "mul", &config, &mut region,
					1,
				)
				.unwrap();

				// p_x_square_times_three = three.result.mul(&p_x_square.result) TODO: ADD THREE
				// This part will be (p_x_square_times three + p_x_square_times three +
				// p_x_square_times three)
				let p_x_square_times_two = Self::wrapper(
					"p_x_square_times_two", &p_x_square, &p_x_square, &reduction_witnesses[2],
					"add", &config, &mut region, 2,
				)
				.unwrap();

				let p_x_square_times_three = Self::wrapper(
					"p_x_square_times_three", &p_x_square, &p_x_square_times_two,
					&reduction_witnesses[3], "add", &config, &mut region, 3,
				)
				.unwrap();

				// m = p_x_square_times_three.result.div(&double_p_y.result)
				let m = Self::wrapper(
					"m", &p_x_square_times_three, &double_p_y, &reduction_witnesses[4], "mul",
					&config, &mut region, 4,
				)
				.unwrap();

				// double_p_x = self.x.add(&self.x)
				let double_p_x = Self::wrapper(
					"double_p_x", &p_x, &p_x, &reduction_witnesses[5], "add", &config, &mut region,
					5,
				)
				.unwrap();

				// m_squared = m.result.mul(&m.result)
				let m_squared = Self::wrapper(
					"m_squared", &m, &m, &reduction_witnesses[6], "mul", &config, &mut region, 6,
				)
				.unwrap();

				// r_x = m_squared.result.sub(&double_p_x.result)
				let r_x = Self::wrapper(
					"r_x", &m_squared, &double_p_x, &reduction_witnesses[7], "add", &config,
					&mut region, 7,
				)
				.unwrap();

				// p_x_minus_r_x = self.x.sub(&r_x.result)
				let p_x_minus_r_x = Self::wrapper(
					"p_x_minus_r_x", &p_x, &r_x, &reduction_witnesses[8], "add", &config,
					&mut region, 8,
				)
				.unwrap();

				// m_times_p_x_minus_r_x = m.result.mul(&p_x_minus_r_x.result)
				let m_times_p_x_minus_r_x = Self::wrapper(
					"m_times_p_x_minus_r_x", &m, &p_x_minus_r_x, &reduction_witnesses[9], "mul",
					&config, &mut region, 9,
				)
				.unwrap();

				// r_y = m_times_p_x_minus_r_x.result.sub(&self.y)
				let r_y = Self::wrapper(
					"r_y", &m_times_p_x_minus_r_x, &p_y, &reduction_witnesses[10], "add", &config,
					&mut region, 10,
				)
				.unwrap();

				Ok((r_x, r_y))
			},
		)
	}

	pub fn mul_scalar(
		// Assigns a cell for the r_x.
		r_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the r_y.
		r_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for r -- make sure r is in the W field before being passed
		r_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigns a cell for the value.
		value: AssignedCell<N, N>,
		// Constructs an array for the value bits.
		value_bits: [N; 256],
		// Reduction witnesses for mul scalar operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc Config
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// Check that `value_bits` are decomposed from `value`
		// for i in 0..value_bits.len() {
		//    if value_bits[i] == 1 {
		//        add selector - row i
		//    }
		//    double selector - row i
		// }
		let bits2num = Bits2NumChip::new(value.clone(), value_bits);
		let bits = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;
		let exp = EcPoint::<W, N, NUM_LIMBS, NUM_BITS, P>::zero();
		layouter.assign_region(
			|| "mul_scalar",
			|mut region: Region<'_, N>| {
				let mut exp_x: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[(); NUM_LIMBS].map(|_| None);
				let mut exp_y: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
					[(); NUM_LIMBS].map(|_| None);
				for i in 0..NUM_LIMBS {
					exp_x[i] = Some(region.assign_advice_from_constant(
						|| "exp_x",
						config.integer.x_limbs[i],
						0,
						N::zero(),
					)?);

					exp_y[i] = Some(region.assign_advice_from_constant(
						|| "exp_y",
						config.integer.y_limbs[i],
						0,
						N::zero(),
					)?);
				}
				let mut exp_x = exp_x.map(|x| x.unwrap());
				let mut exp_y = exp_y.map(|x| x.unwrap());

				for i in 0..value_bits.len() {
					/*
					if value_bits[i] == N::one() {

						(exp_x, exp_y) = Self::add(
							r_x.clone(),
							r_y.clone(),
							exp_x.clone(),
							exp_y.clone(),
							reduction_witnesses.clone(),
							config.clone(),
							layouter.clone(),
						)
						.unwrap();
					}
					(exp_x, exp_y) = Self::double(
						exp_x.clone(),
						exp_y.clone(),
						exp.reduction_witnesses.clone(),
						config.clone(),
						layouter.clone(),
					)
					.unwrap();
					*/
				}

				Ok((r_x.clone(), r_y.clone()))
			},
		)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use crate::{
		ecc::native::EcPoint,
		integer::{
			native::{Integer, ReductionWitness},
			rns::{Bn256_4_68, RnsParams},
		},
	};
	use bellman_ce::{bn256::G1, CurveProjective};
	use halo2wrong::{
		curves::{
			bn256::{Fq, Fr},
			FieldExt,
		},
		halo2::{
			circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
		},
	};
	use num_bigint::BigUint;

	use super::{EccChip, EccConfig};

	#[derive(Clone)]
	enum Gadgets {
		Double,
	}

	#[derive(Clone, Debug)]
	struct TestConfig<const NUM_LIMBS: usize> {
		ecc: EccConfig<NUM_LIMBS>,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		a: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		gadget: Gadgets,
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
		TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		fn new(
			a: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
			rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
			reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
			gadget: Gadgets,
		) -> Self {
			Self { a, rw, reduction_witnesses, gadget }
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
			let ecc = EccChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(instance);

			TestConfig { ecc, temp, pub_ins: instance }
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
							|| Value::known(self.a.x.limbs[i]),
						)?;

						let y = region.assign_advice(
							|| "temp_y",
							config.temp,
							i + NUM_LIMBS,
							|| Value::known(self.a.y.limbs[i]),
						)?;

						x_limbs[i] = Some(x);
						y_limbs[i] = Some(y);
					}

					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|y| y.unwrap())))
				},
			)?;

			let res = match self.gadget {
				Gadgets::Double => EccChip::double(
					x_limbs_assigned,
					y_limbs_assigned,
					self.reduction_witnesses.clone(),
					config.ecc.clone(),
					layouter.namespace(|| "mul"),
				)?,
			};
			Ok(())
		}
	}

	#[test]
	fn should_add_two_points() {}

	#[test]
	fn should_double_a_point() {
		// Testing double.
		let a_big = BigUint::from_str("1").unwrap();
		let b_big = BigUint::from_str("1").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let a_point = EcPoint::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), b.clone());
		let res = a.add(&b);
		let rw = a_point.double();
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			a_point,
			res.clone(),
			rw.reduction_witnesses,
			Gadgets::Double,
		);

		let k = 6;
		let mut g1_bell = G1::one();
		g1_bell.double();
		println!("{:#?}", g1_bell);

		let p_ins = vec![Fr::one()];
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_with_scalar() {}
}
