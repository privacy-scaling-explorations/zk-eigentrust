/// Native version of the chip
pub mod native;

use std::marker::PhantomData;

use crate::{
	gadgets::{
		bits2num::{Bits2NumChip, Bits2NumConfig},
		common::{CommonChip, CommonConfig},
	},
	integer::{
		native::{Integer, Quotient, ReductionWitness},
		rns::RnsParams,
		AssignedInteger, IntegerChip, IntegerConfig,
	},
};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error},
};

struct AssignedPoint<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a new `AssignedPoint` given its coordinates as `AssignedInteger`
	pub fn new(
		x: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P> {
		AssignedPoint { x, y }
	}

	/// Returns $x$ coordinate
	pub fn x(&self) -> AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P> {
		self.x.clone()
	}

	/// Returns $y$ coordinate
	pub fn y(&self) -> AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P> {
		self.y.clone()
	}
}

#[derive(Debug, Clone)]
struct EccConfig<const NUM_LIMBS: usize> {
	bits2num: Bits2NumConfig,
	integer: IntegerConfig<NUM_LIMBS>,
	common: CommonConfig,
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
	fn assign(
		x_opt: Option<&[AssignedCell<N, N>; NUM_LIMBS]>, y: &[AssignedCell<N, N>; NUM_LIMBS],
		reduction_witness: &ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		config: &EccConfig<NUM_LIMBS>, region: &mut Region<'_, N>, row: usize,
	) -> Result<[AssignedCell<N, N>; NUM_LIMBS], Error> {
		match &reduction_witness.quotient {
			Quotient::Short(n) => {
				region.assign_advice(
					|| "quotient",
					config.integer.quotient[0],
					row,
					|| Value::known(*n),
				)?;
			},
			Quotient::Long(n) => {
				for i in 0..NUM_LIMBS {
					region.assign_advice(
						|| format!("quotient_{}", i),
						config.integer.quotient[i],
						row,
						|| Value::known(n.limbs[i]),
					)?;
				}
			},
		}

		for i in 0..NUM_LIMBS {
			if x_opt.is_some() {
				let x = x_opt.unwrap();
				x[i].copy_advice(
					|| format!("limb_x_{}", i),
					region,
					config.integer.x_limbs[i],
					row,
				)?;
			}
			y[i].copy_advice(
				|| format!("limb_y_{}", i),
				region,
				config.integer.y_limbs[i],
				row,
			)?;

			region.assign_advice(
				|| format!("intermediates_{}", i),
				config.integer.intermediate[i],
				row,
				|| Value::known(reduction_witness.intermediate[i]),
			)?;
		}

		for i in 0..reduction_witness.residues.len() {
			region.assign_advice(
				|| format!("residues_{}", i),
				config.integer.residues[i],
				row,
				|| Value::known(reduction_witness.residues[i]),
			)?;
		}

		let mut assigned_result: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			assigned_result[i] = Some(region.assign_advice(
				|| format!("result_{}", i),
				config.integer.x_limbs[i],
				row + 1,
				|| Value::known(reduction_witness.result.limbs[i]),
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
		let common = CommonChip::configure(meta);

		EccConfig { bits2num, integer, common }
	}

	pub fn add_reduced(
		// Assigned point p
		p: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigned point p
		q: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for add operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc config columns
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>, Error> {
		let p_x = AssignedInteger::new(
			IntegerChip::reduce(
				p.x().integer,
				p.x().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_p_x"),
			)?,
			p.x().rw,
		);
		let p_y = AssignedInteger::new(
			IntegerChip::reduce(
				p.y().integer,
				p.y().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_p_y"),
			)?,
			p.y().rw,
		);
		let q_x = AssignedInteger::new(
			IntegerChip::reduce(
				q.x().integer,
				q.x().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_q_x"),
			)?,
			q.x().rw,
		);
		let q_y = AssignedInteger::new(
			IntegerChip::reduce(
				q.y().integer,
				q.y().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_q_y"),
			)?,
			q.y().rw,
		);

		let p = AssignedPoint::new(p_x, p_y);
		let q = AssignedPoint::new(q_x, q_y);

		let point = Self::add_unreduced(
			p,
			q,
			reduction_witnesses,
			config,
			layouter.namespace(|| "reduce_add"),
		)?;
		Ok(point)
	}

	pub fn add_unreduced(
		// Assigned point p
		p: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigned point q
		q: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for add operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc config columns
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>, Error> {
		// Assign a region where we use columns from Integer chip
		// sub selector - row 0
		// sub selector - row 2
		// div selector - row 4
		// mul selector - row 5
		// sub selector - row 6
		// sub selector - row 7
		// sub selector - row 8
		// mul selector - row 9
		// sub selector - row 10
		layouter.assign_region(
			|| "elliptic_add_operation",
			|mut region: Region<'_, N>| {
				// numerator = other.y.sub(&self.y);
				config.integer.sub_selector.enable(&mut region, 0)?;
				let numerator = IntegerChip::assign(
					Some(&q.y.integer),
					&p.y.integer,
					&reduction_witnesses[0],
					&config.integer,
					&mut region,
					0,
				)
				.unwrap();

				// denominator = other.x.sub(&self.x);
				config.integer.sub_selector.enable(&mut region, 2)?;
				let denominator = IntegerChip::assign(
					Some(&q.x.integer),
					&p.x.integer,
					&reduction_witnesses[1],
					&config.integer,
					&mut region,
					2,
				)
				.unwrap();

				// m = numerator.result.div(&denominator.result)
				config.integer.div_selector.enable(&mut region, 4)?;
				let m = IntegerChip::assign(
					Some(&numerator),
					&denominator,
					&reduction_witnesses[2],
					&config.integer,
					&mut region,
					4,
				)
				.unwrap();

				// m_squared = m.result.mul(&m.result)
				config.integer.mul_selector.enable(&mut region, 5)?;
				let _m_squared = IntegerChip::assign(
					None, &m, &reduction_witnesses[3], &config.integer, &mut region, 5,
				)
				.unwrap();

				// m_squared_minus_p_x = m_squared.result.sub(&self.x)
				config.integer.sub_selector.enable(&mut region, 6)?;
				let _m_squared_minus_p_x = IntegerChip::assign(
					None, &p.x.integer, &reduction_witnesses[4], &config.integer, &mut region, 6,
				)
				.unwrap();

				// r_x = m_squared_minus_p_x.result.sub(&other.x)
				config.integer.sub_selector.enable(&mut region, 7)?;
				let r_x = IntegerChip::assign(
					None, &q.x.integer, &reduction_witnesses[5], &config.integer, &mut region, 7,
				)
				.unwrap();

				// r_x_minus_p_x = self.x.sub(&r_x.result);
				config.integer.sub_selector.enable(&mut region, 9)?;
				let r_x_minus_p_x = IntegerChip::assign(
					Some(&p.x.integer),
					&r_x,
					&reduction_witnesses[6],
					&config.integer,
					&mut region,
					9,
				)
				.unwrap();

				// m_times_r_x_minus_p_x = m.result.mul(&r_x_minus_p_x.result);
				config.integer.mul_selector.enable(&mut region, 11)?;
				let _m_times_r_x_minus_p_x = IntegerChip::assign(
					Some(&m),
					&r_x_minus_p_x,
					&reduction_witnesses[7],
					&config.integer,
					&mut region,
					11,
				)
				.unwrap();

				// r_y = m_times_r_x_minus_p_x.result.sub(&self.y)
				config.integer.sub_selector.enable(&mut region, 12)?;
				let r_y = IntegerChip::assign(
					None, &p.y.integer, &reduction_witnesses[8], &config.integer, &mut region, 12,
				)
				.unwrap();

				let r_x = AssignedInteger::new(r_x, reduction_witnesses[5].clone());
				let r_y = AssignedInteger::new(r_y, reduction_witnesses[8].clone());
				let r = AssignedPoint::new(r_x, r_y);
				Ok(r)
			},
		)
	}

	pub fn double_reduced(
		// Assigned point p
		p: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for add operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc config columns
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>, Error> {
		let p_x = AssignedInteger::new(
			IntegerChip::reduce(
				p.x().integer,
				p.x().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_p_x"),
			)?,
			p.x().rw,
		);
		let p_y = AssignedInteger::new(
			IntegerChip::reduce(
				p.y().integer,
				p.y().rw,
				config.integer.clone(),
				layouter.namespace(|| "reduce_p_y"),
			)?,
			p.y().rw,
		);

		let p = AssignedPoint::new(p_x, p_y);
		let point = Self::double_unreduced(
			p,
			reduction_witnesses,
			config,
			layouter.namespace(|| "reduce_double"),
		)?;
		Ok(point)
	}

	pub fn double_unreduced(
		p: AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for double operation
		reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc Config
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<AssignedPoint<W, N, NUM_LIMBS, NUM_BITS, P>, Error> {
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
			|| "elliptic_double_operation",
			|mut region: Region<'_, N>| {
				// double_p_y = self.y.add(&self.y)
				config.integer.add_selector.enable(&mut region, 0)?;
				let double_p_y = IntegerChip::assign(
					Some(&p.y().integer),
					&p.y().integer,
					&reduction_witnesses[0],
					&config.integer,
					&mut region,
					0,
				)
				.unwrap();

				// p_x_square = self.x.mul(&self.x)
				config.integer.mul_selector.enable(&mut region, 2)?;
				let p_x_square = IntegerChip::assign(
					Some(&p.x().integer),
					&p.x().integer,
					&reduction_witnesses[1],
					&config.integer,
					&mut region,
					2,
				)
				.unwrap();

				// p_x_square_times_two = p_x_square.result.add(&p_x_square.result);
				config.integer.add_selector.enable(&mut region, 3)?;
				let _p_x_square_times_two = IntegerChip::assign(
					None, &p_x_square, &reduction_witnesses[2], &config.integer, &mut region, 3,
				)
				.unwrap();

				// p_x_square_times_three = p_x_square.result.add(&p_x_square_times_two.result);
				config.integer.add_selector.enable(&mut region, 4)?;
				let _p_x_square_times_three = IntegerChip::assign(
					None, &p_x_square, &reduction_witnesses[3], &config.integer, &mut region, 4,
				)
				.unwrap();

				// m = p_x_square_times_three.result.div(&double_p_y.result)
				config.integer.div_selector.enable(&mut region, 5)?;
				let m = IntegerChip::assign(
					None, &double_p_y, &reduction_witnesses[4], &config.integer, &mut region, 5,
				)
				.unwrap();

				// double_p_x = self.x.add(&self.x)
				config.integer.add_selector.enable(&mut region, 7)?;
				let double_p_x = IntegerChip::assign(
					Some(&p.x().integer),
					&p.x().integer,
					&reduction_witnesses[5],
					&config.integer,
					&mut region,
					7,
				)
				.unwrap();

				// m_squared = m.result.mul(&m.result)
				config.integer.mul_selector.enable(&mut region, 9)?;
				let _m_squared = IntegerChip::assign(
					Some(&m),
					&m,
					&reduction_witnesses[6],
					&config.integer,
					&mut region,
					9,
				)
				.unwrap();

				// r_x = m_squared.result.sub(&double_p_x.result)
				config.integer.sub_selector.enable(&mut region, 10)?;
				let r_x = IntegerChip::assign(
					None, &double_p_x, &reduction_witnesses[7], &config.integer, &mut region, 10,
				)
				.unwrap();

				// p_x_minus_r_x = self.x.sub(&r_x.result)
				config.integer.sub_selector.enable(&mut region, 12)?;
				let _p_x_minus_r_x = IntegerChip::assign(
					Some(&p.x().integer),
					&r_x,
					&reduction_witnesses[8],
					&config.integer,
					&mut region,
					12,
				)
				.unwrap();

				// m_times_p_x_minus_r_x = m.result.mul(&p_x_minus_r_x.result)
				config.integer.mul_selector.enable(&mut region, 13)?;
				let _m_times_p_x_minus_r_x = IntegerChip::assign(
					None, &m, &reduction_witnesses[9], &config.integer, &mut region, 13,
				)
				.unwrap();

				// r_y = m_times_p_x_minus_r_x.result.sub(&self.y)
				config.integer.sub_selector.enable(&mut region, 14)?;
				let r_y = IntegerChip::assign(
					None,
					&p.y().integer,
					&reduction_witnesses[10],
					&config.integer,
					&mut region,
					14,
				)
				.unwrap();

				let r_x = AssignedInteger::new(r_x, reduction_witnesses[7].clone());
				let r_y = AssignedInteger::new(r_y, reduction_witnesses[10].clone());
				let r = AssignedPoint::new(r_x, r_y);

				Ok(r)
			},
		)
	}

	/*
	pub fn mul_scalar(
		// Assigns a cell for the r_x.
		exp_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the r_y.
		exp_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for exp_x -- make sure exp_x is in the W field before being passed
		exp_x_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witness for exp_y -- make sure exp_y is in the W field before being passed
		exp_y_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigns a cell for the value.
		value: AssignedCell<N, N>,
		// Constructs an array for the value bits.
		value_bits: [N; 256],
		// Reduction witnesses for mul scalar add operation
		reduction_witnesses_add: [Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256],
		// Reduction witnesses for mul scalar double operation
		reduction_witnesses_double: [Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256],
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
		let mut exp_x = IntegerChip::reduce(
			exp_x,
			exp_x_rw,
			config.integer.clone(),
			layouter.namespace(|| "reduce_exp_x"),
		)?;
		let mut exp_y = IntegerChip::reduce(
			exp_y,
			exp_y_rw,
			config.integer.clone(),
			layouter.namespace(|| "reduce_exp_y"),
		)?;
		let mut exps = Vec::new();
		for i in 0..bits.len() {
			(exp_x, exp_y) = Self::double_unreduced(
				exp_x.clone(),
				exp_y.clone(),
				reduction_witnesses_double[i].clone(),
				config.clone(),
				layouter.namespace(|| "doubling"),
			)?;
			exps.push((exp_x.clone(), exp_y.clone()));
		}
		// Find first positive bit
		let first_bit = Self::find_first_positive_bit(value_bits);
		let mut r_x = exps[first_bit].0.clone();
		let mut r_y = exps[first_bit].1.clone();
		let mut flag = true;
		/*
				for i in (first_bit + 1)..bits.len() {
					// Here we pass this checks because we assigned(exp_x, exp_y) to (r_x,
					// r_y) and we already constraint them when we calculate double operation. After
					// we hit second positive bit we start to check addition constraints as well.
					if (value_bits[i] == N::zero()) && flag {
						continue;
					} else {
						flag = false;
						let (new_r_x, new_r_y) = Self::add_unreduced(
							r_x.clone(),
							r_y.clone(),
							exps[i].0.clone(),
							exps[i].1.clone(),
							reduction_witnesses_add[i].clone(),
							config.clone(),
							layouter.namespace(|| "add"),
						)?;

						for j in 0..NUM_LIMBS {
							// r_x
							r_x[j] = CommonChip::select(
								bits[i].clone(),
								new_r_x[j].clone(),
								r_x[j].clone(),
								config.common,
								layouter.namespace(|| format!("select_r_x_{}", j)),
							)?;

							// r_y
							r_y[j] = CommonChip::select(
								bits[i].clone(),
								new_r_y[j].clone(),
								r_y[j].clone(),
								config.common,
								layouter.namespace(|| format!("select_r_y_{}", j)),
							)?;
						}
					}
				}
		*/
		Ok((r_x, r_y))
	}

	fn find_first_positive_bit(input: [N; 256]) -> usize {
		let mut counter = 0;
		for i in 0..256 {
			if input[i] == N::one() {
				break;
			}
			counter += 1;
		}
		counter
	}
	*/
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use crate::{
		ecc::{native::EcPoint, test},
		integer::{
			native::{Integer, ReductionWitness},
			rns::{Bn256_4_68, RnsParams},
			AssignedInteger,
		},
	};
	use halo2wrong::{
		curves::{
			bn256::{Fq, Fr},
			FieldExt,
		},
		halo2::{
			arithmetic::Field,
			circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
		},
	};
	use num_bigint::BigUint;
	use rand::thread_rng;

	use super::{AssignedPoint, EccChip, EccConfig};

	#[derive(Clone)]
	enum Gadgets {
		Add,
		Double,
		//Mul,
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
		p: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
		p_x_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		p_y_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		q: Option<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>>,
		q_x_rw: Option<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		q_y_rw: Option<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		reduction_witnesses: Option<Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>>,
		reduction_witnesses_add: Option<[Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256]>,
		reduction_witnesses_double:
			Option<[Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256]>,
		value: Option<N>,
		value_bits: Option<[N; 256]>,
		gadget: Gadgets,
	}

	impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
		TestCircuit<W, N, NUM_LIMBS, NUM_BITS, P>
	where
		P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
	{
		fn new(
			p: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>,
			p_x_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
			p_y_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
			q: Option<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>>,
			q_x_rw: Option<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
			q_y_rw: Option<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
			reduction_witnesses: Option<Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>>,
			reduction_witnesses_add: Option<
				[Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256],
			>,
			reduction_witnesses_double: Option<
				[Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>; 256],
			>,
			value: Option<N>, value_bits: Option<[N; 256]>, gadget: Gadgets,
		) -> Self {
			Self {
				p,
				p_x_rw,
				p_y_rw,
				q,
				q_x_rw,
				q_y_rw,
				reduction_witnesses,
				reduction_witnesses_add,
				reduction_witnesses_double,
				value,
				value_bits,
				gadget,
			}
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
			let value = layouter.assign_region(
				|| "scalar_mul_values",
				|mut region: Region<'_, N>| {
					let mut zero_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut one_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let value = region.assign_advice(
						|| "value",
						config.temp,
						0,
						|| Value::known(self.value.unwrap_or(N::zero())),
					)?;

					Ok(value)
				},
			)?;

			let (p_x_limbs_assigned, p_y_limbs_assigned) = layouter.assign_region(
				|| "p_temp",
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
							|| Value::known(self.p.x.limbs[i]),
						)?;

						let y = region.assign_advice(
							|| "temp_y",
							config.temp,
							i + NUM_LIMBS,
							|| Value::known(self.p.y.limbs[i]),
						)?;

						x_limbs[i] = Some(x);
						y_limbs[i] = Some(y);
					}

					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|y| y.unwrap())))
				},
			)?;

			let (q_x_limbs_assigned, q_y_limbs_assigned) = layouter.assign_region(
				|| "q_temp",
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
							|| {
								Value::known(
									self.q.clone().map(|p| p.x.limbs[i]).unwrap_or(N::zero()),
								)
							},
						)?;
						let y = region.assign_advice(
							|| "temp_y",
							config.temp,
							i + NUM_LIMBS,
							|| {
								Value::known(
									self.q.clone().map(|p| p.y.limbs[i]).unwrap_or(N::zero()),
								)
							},
						)?;

						x_limbs[i] = Some(x);
						y_limbs[i] = Some(y);
					}

					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|x| x.unwrap())))
				},
			)?;

			let p_x_int = AssignedInteger::new(p_x_limbs_assigned, self.p_x_rw.clone());
			let p_y_int = AssignedInteger::new(p_y_limbs_assigned, self.p_y_rw.clone());

			let p = AssignedPoint::new(p_x_int, p_y_int);

			let point = match self.gadget {
				Gadgets::Double => EccChip::double_reduced(
					p,
					self.reduction_witnesses.clone().unwrap(),
					config.ecc.clone(),
					layouter.namespace(|| "double"),
				)?,
				Gadgets::Add => {
					let q_x_int =
						AssignedInteger::new(q_x_limbs_assigned, self.q_x_rw.clone().unwrap());
					let q_y_int =
						AssignedInteger::new(q_y_limbs_assigned, self.q_y_rw.clone().unwrap());
					let q = AssignedPoint::new(q_x_int, q_y_int);

					EccChip::add_reduced(
						p,
						q,
						self.reduction_witnesses.clone().unwrap(),
						config.ecc.clone(),
						layouter.namespace(|| "add"),
					)?
				},
				/*
				Gadgets::Mul => EccChip::mul_scalar(
					p_x_limbs_assigned,
					p_y_limbs_assigned,
					self.p_x_rw.clone(),
					self.p_y_rw.clone(),
					value,
					self.value_bits.unwrap(),
					self.reduction_witnesses_add.clone().unwrap(),
					self.reduction_witnesses_double.clone().unwrap(),
					config.ecc.clone(),
					layouter.namespace(|| "scalar_mul"),
				)?,
				*/
			};

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(point.x().integer[i].cell(), config.pub_ins, i)?;
				layouter.constrain_instance(
					point.y().integer[i].cell(),
					config.pub_ins,
					i + NUM_LIMBS,
				)?;
			}
			Ok(())
		}
	}

	#[test]
	fn should_add_two_points() {
		// Testing add.
		let zero = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::zero();
		let a_big = BigUint::from_str("23423423525345345").unwrap();
		let b_big = BigUint::from_str("65464575675").unwrap();
		let c_big = BigUint::from_str("23423423423425345647567567568").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(c_big);
		let p_point = EcPoint::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), b.clone());
		let q_point = EcPoint::<Fq, Fr, 4, 68, Bn256_4_68>::new(b.clone(), c.clone());
		let rw_p_x = a.add(&zero);
		let rw_p_y = b.add(&zero);
		let rw_q_x = b.add(&zero);
		let rw_q_y = c.add(&zero);

		let res = p_point.add(&q_point);
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			p_point,
			rw_p_x.clone(),
			rw_p_y.clone(),
			Some(q_point),
			Some(rw_q_x.clone()),
			Some(rw_q_y.clone()),
			Some(res.reduction_witnesses),
			None,
			None,
			None,
			None,
			Gadgets::Add,
		);

		let k = 6;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_double_a_point() {
		// Testing double.
		let zero = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::zero();
		let a_big = BigUint::from_str("23423423525345345").unwrap();
		let b_big = BigUint::from_str("65464575675").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let p_point = EcPoint::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), b.clone());
		let rw_p_x = a.add(&zero);
		let rw_p_y = b.add(&zero);

		let res = p_point.double();
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			p_point,
			rw_p_x.clone(),
			rw_p_y.clone(),
			None,
			None,
			None,
			Some(res.reduction_witnesses),
			None,
			None,
			None,
			None,
			Gadgets::Double,
		);

		let k = 6;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
	/*
	#[test]
	#[ignore = "Mul scalar broken"]
	fn should_mul_with_scalar() {
		// Testing scalar multiplication.
		let rng = &mut thread_rng();
		let scalar = Fr::from_u128(30);
		let zero = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::zero();
		let a_big = BigUint::from_str("2342342453654645641233").unwrap();
		let b_big = BigUint::from_str("1231231231234235346457675685645454").unwrap();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let p_point = EcPoint::<Fq, Fr, 4, 68, Bn256_4_68>::new(a.clone(), b.clone());
		let p_point = p_point.double();
		let rw_p_x = p_point.x.add(&zero);
		let rw_p_y = p_point.y.add(&zero);

		let bits = scalar.to_bytes().map(|byte| {
			let mut byte_bits = [false; 8];
			for i in (0..8).rev() {
				byte_bits[i] = (byte >> i) & 1u8 != 0
			}
			byte_bits
		});
		let mut bits_fr = [Fr::zero(); 256];
		for i in 0..256 {
			bits_fr[i] = Fr::from_u128(bits.flatten()[i].into())
		}

		let res = p_point.mul_scalar(scalar.to_bytes());
		let test_chip = TestCircuit::<Fq, Fr, 4, 68, Bn256_4_68>::new(
			p_point.clone(),
			rw_p_x.clone(),
			rw_p_y.clone(),
			Some(p_point.clone()),
			Some(rw_p_x.clone()),
			Some(rw_p_y.clone()),
			None,
			Some(res.1.clone()),
			Some(res.2.clone()),
			Some(scalar.clone()),
			Some(bits_fr),
			Gadgets::Mul,
		);
		let k = 13;
		let mut p_ins = Vec::new();
		p_ins.extend(res.0.x.limbs);
		p_ins.extend(res.0.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		let errs = prover.verify().err().unwrap();
		for err in errs {
			println!("{:?}", err);
		}
		//assert_eq!(prover.verify(), Ok(()));
	}
	*/
}
