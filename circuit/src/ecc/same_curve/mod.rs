/// Native version of the chip
pub mod native;

use crate::{
	gadgets::{
		bits2num::Bits2NumChip,
		main::{MainConfig, SelectChipset},
	},
	integer::{
		AssignedInteger, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
		IntegerSubChip,
	},
	params::rns::RnsParams,
	utils::{assigned_as_bool, be_assigned_bits_to_usize},
	Chip, Chipset, CommonConfig, FieldExt,
};
use halo2::halo2curves::ff::PrimeField;
use halo2::{
	circuit::{AssignedCell, Layouter},
	halo2curves::CurveAffine,
	plonk::{Error, Selector},
};

/// Structure for the AssignedPoint.
#[derive(Clone, Debug)]
pub struct AssignedPoint<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// x coordinate of the point
	pub(crate) x: AssignedInteger<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	// y coordinate of the point
	pub(crate) y: AssignedInteger<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns a new `AssignedPoint` given its coordinates as `AssignedInteger`
	pub fn new(
		x: AssignedInteger<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
		y: AssignedInteger<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	) -> AssignedPoint<C, NUM_LIMBS, NUM_BITS, P> {
		AssignedPoint { x, y }
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccAddConfig {
	/// Constructs selectors from different circuits.
	integer_reduce_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccAddConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_reduce_selector: Selector, integer_sub_selector: Selector,
		integer_mul_selector: Selector, integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_reduce_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Chipset structure for the EccAdd.
pub struct EccAddChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned point p
	p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// Assigned point q
	q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccAddChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc add chipset.
	pub fn new(
		p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>, q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { p, q }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccAddChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccAddConfig;
	type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		// Reduce p_x
		let p_x = IntegerReduceChip::new(self.p.x);
		let p_x_reduced = p_x.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_p_x"),
		)?;

		// Reduce p_y
		let p_y = IntegerReduceChip::new(self.p.y);
		let p_y_reduced = p_y.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_p_y"),
		)?;

		// Reduce q_x
		let q_x = IntegerReduceChip::new(self.q.x);
		let q_x_reduced = q_x.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_q_x"),
		)?;

		// Reduce q_y
		let q_y = IntegerReduceChip::new(self.q.y);
		let q_y_reduced = q_y.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_q_y"),
		)?;

		// numerator = q.y.sub(&p.y);
		let numerator_chip = IntegerSubChip::new(q_y_reduced, p_y_reduced.clone());
		let numerator = numerator_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "numerator"),
		)?;

		// denominator = q.x.sub(&p.x);
		let denominator_chip = IntegerSubChip::new(q_x_reduced.clone(), p_x_reduced.clone());
		let denominator = denominator_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "denominator"),
		)?;

		// m = numerator.result.div(&denominator.result)
		let m_chip = IntegerDivChip::new(numerator, denominator);
		let m = m_chip.synthesize(
			common,
			&config.integer_div_selector,
			layouter.namespace(|| "m"),
		)?;

		// m_squared = m.result.mul(&m.result)
		let m_squared_chip = IntegerMulChip::new(m.clone(), m.clone());
		let m_squared = m_squared_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_squared"),
		)?;

		// m_squared_minus_p_x = m_squared.result.sub(&p.x)
		let m_squared_minus_p_x_chip = IntegerSubChip::new(m_squared, p_x_reduced.clone());
		let m_squared_minus_p_x = m_squared_minus_p_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "m_squared_minus_p_x"),
		)?;

		// r_x = m_squared_minus_p_x.result.sub(&q.x)
		let r_x_chip = IntegerSubChip::new(m_squared_minus_p_x, q_x_reduced);
		let r_x = r_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_x"),
		)?;

		// r_x_minus_p_x = p.x.sub(&r_x.result);
		let r_x_minus_p_x_chip = IntegerSubChip::new(p_x_reduced, r_x.clone());
		let r_x_minus_p_x = r_x_minus_p_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_x_minus_p_x"),
		)?;

		// m_times_r_x_minus_p_x = m.result.mul(&r_x_minus_p_x.result);
		let m_times_r_x_minus_p_x_chip = IntegerMulChip::new(m, r_x_minus_p_x);
		let m_times_r_x_minus_p_x = m_times_r_x_minus_p_x_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_times_r_x_minus_p_x"),
		)?;

		// r_y = m_times_r_x_minus_p_x.result.sub(&p.y)
		let r_y_chip = IntegerSubChip::new(m_times_r_x_minus_p_x, p_y_reduced);
		let r_y = r_y_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_y"),
		)?;

		let r = AssignedPoint::new(r_x, r_y);
		Ok(r)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccDoubleConfig {
	/// Constructs selectors from different circuits.
	integer_reduce_selector: Selector,
	integer_add_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccDoubleConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_reduce_selector: Selector, integer_add_selector: Selector,
		integer_sub_selector: Selector, integer_mul_selector: Selector,
		integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_reduce_selector,
			integer_add_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Chipset structure for the EccDouble.
struct EccDoubleChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned point p
	p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccDoubleChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc double chipset.
	pub fn new(p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { p }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccDoubleChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccDoubleConfig;
	type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		// Reduce p_x
		let p_x = IntegerReduceChip::new(self.p.x.clone());
		let p_x_reduced = p_x.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_p_x"),
		)?;

		// Reduce p_y
		let p_y = IntegerReduceChip::new(self.p.y);
		let p_y_reduced = p_y.synthesize(
			common,
			&config.integer_reduce_selector,
			layouter.namespace(|| "reduce_p_y"),
		)?;

		// double_p_y = p.y.add(&p.y)
		let double_p_y_chip = IntegerAddChip::new(p_y_reduced.clone(), p_y_reduced.clone());
		let double_p_y = double_p_y_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "double_p_y"),
		)?;

		// p_x_square = p.x.mul(&p.x)
		let p_x_square_chip = IntegerMulChip::new(p_x_reduced.clone(), p_x_reduced.clone());
		let p_x_square = p_x_square_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "p_x_square"),
		)?;

		// p_x_square_times_two = p_x_square.result.add(&p_x_square.result);
		let p_x_square_times_two_chip = IntegerAddChip::new(p_x_square.clone(), p_x_square.clone());
		let p_x_square_times_two = p_x_square_times_two_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "p_x_square_times_two"),
		)?;

		// p_x_square_times_three = p_x_square.result.add(&p_x_square_times_two.result);
		let p_x_square_times_three_chip = IntegerAddChip::new(p_x_square_times_two, p_x_square);
		let p_x_square_times_three = p_x_square_times_three_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "p_x_square_times_three"),
		)?;

		// m = p_x_square_times_three.result.div(&double_p_y.result)
		let m_chip = IntegerDivChip::new(p_x_square_times_three, double_p_y);
		let m = m_chip.synthesize(
			common,
			&config.integer_div_selector,
			layouter.namespace(|| "m"),
		)?;

		// double_p_x = p.x.add(&p.x)
		let double_p_x_chip = IntegerAddChip::new(p_x_reduced.clone(), p_x_reduced.clone());
		let double_p_x = double_p_x_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "double_p_x"),
		)?;

		// m_squared = m.result.mul(&m.result)
		let m_squared_chip = IntegerMulChip::new(m.clone(), m.clone());
		let m_squared = m_squared_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_squared"),
		)?;

		// r_x = m_squared.result.sub(&double_p_x.result)
		let r_x_chip = IntegerSubChip::new(m_squared, double_p_x);
		let r_x = r_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_x"),
		)?;

		// p_x_minus_r_x = self.x.sub(&r_x.result)
		let p_x_minus_r_x_chip = IntegerSubChip::new(p_x_reduced, r_x.clone());
		let p_x_minus_r_x = p_x_minus_r_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "p_x_minus_r_x"),
		)?;

		// m_times_p_x_minus_r_x = m.result.mul(&p_x_minus_r_x.result)
		let m_times_p_x_minus_r_x_chip = IntegerMulChip::new(m, p_x_minus_r_x);
		let m_times_p_x_minus_r_x = m_times_p_x_minus_r_x_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_times_p_x_minus_r_x"),
		)?;

		// r_y = m_times_p_x_minus_r_x.result.sub(&p.y)
		let r_y_chip = IntegerSubChip::new(m_times_p_x_minus_r_x, p_y_reduced);
		let r_y = r_y_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_y"),
		)?;

		let r = AssignedPoint::new(r_x, r_y);
		Ok(r)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccUnreducedLadderConfig {
	/// Constructs selectors from different circuits.
	integer_add_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccUnreducedLadderConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_add_selector: Selector, integer_sub_selector: Selector,
		integer_mul_selector: Selector, integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_add_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Chipset structure for the EccUnreducedLadder.
struct EccUnreducedLadderChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned point p
	p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// Assigned point q
	q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccUnreducedLadderChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc unreduced ladder chipset.
	pub fn new(
		p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>, q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { p, q }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccUnreducedLadderChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccUnreducedLadderConfig;
	type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		// numerator = q.y.sub(&p.y)
		let numerator_chip = IntegerSubChip::new(self.q.y, self.p.y.clone());
		let numerator = numerator_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "numerator"),
		)?;

		// denominator = q.x.sub(&p.x)
		let denominator_chip = IntegerSubChip::new(self.q.x.clone(), self.p.x.clone());
		let denominator = denominator_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "denominator"),
		)?;

		// m_zero = numerator.result.div(&denominator.result)
		let m_zero_chip = IntegerDivChip::new(numerator, denominator);
		let m_zero = m_zero_chip.synthesize(
			common,
			&config.integer_div_selector,
			layouter.namespace(|| "m_zero"),
		)?;

		// m_zero_squared = m_zero.result.mul(&m_zero.result)
		let m_zero_squared_chip = IntegerMulChip::new(m_zero.clone(), m_zero.clone());
		let m_zero_squared = m_zero_squared_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_zero_squared"),
		)?;

		// m_zero_squared_minus_p_x = m_zero_squared.result.sub(&p.x)
		let m_zero_squared_minus_p_x_chip = IntegerSubChip::new(m_zero_squared, self.p.x.clone());
		let m_zero_squared_minus_p_x = m_zero_squared_minus_p_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "m_zero_squared_minus_p_x"),
		)?;

		// x_three = m_zero_squared_minus_p_x.result.sub(&q.x)
		let x_three_chip = IntegerSubChip::new(m_zero_squared_minus_p_x, self.q.x.clone());
		let x_three = x_three_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "x_three"),
		)?;

		// double_p_y = p.y.add(&p.y);
		let double_p_y_chip = IntegerAddChip::new(self.p.y.clone(), self.p.y.clone());
		let double_p_y = double_p_y_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "double_p_y"),
		)?;

		// denom_m_one = x_three.result.sub(&double_p_y.result);
		let denom_m_one_chip = IntegerSubChip::new(x_three.clone(), self.p.x.clone());
		let denom_m_one = denom_m_one_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "denom_m_one"),
		)?;

		// div_res = double_p_y.result.div(&denom_m_one)
		let div_res_chip = IntegerDivChip::new(double_p_y, denom_m_one);
		let div_res = div_res_chip.synthesize(
			common,
			&config.integer_div_selector,
			layouter.namespace(|| "div_res"),
		)?;

		// m_one = m_zero.result.add(&div_res.result);
		let m_one_chip = IntegerAddChip::new(m_zero, div_res);
		let m_one = m_one_chip.synthesize(
			common,
			&config.integer_add_selector,
			layouter.namespace(|| "m_one"),
		)?;

		// m_one_squared = m_one.result.mul(&m_one.result);
		let m_one_squared_chip = IntegerMulChip::new(m_one.clone(), m_one.clone());
		let m_one_squared = m_one_squared_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_one_squared"),
		)?;

		// m_one_squared_minus_r_x =
		// m_one_squared.result.sub(&x_three.result);
		let m_one_squared_minus_r_x_chip = IntegerSubChip::new(m_one_squared, x_three);
		let m_one_squared_minus_r_x = m_one_squared_minus_r_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "m_one_squared_minus_r_x"),
		)?;

		// r_x = m_one_squared_minus_r_x.result.sub(&p.x);
		let r_x_chip = IntegerSubChip::new(m_one_squared_minus_r_x, self.p.x.clone());
		let r_x = r_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_x"),
		)?;

		// r_x_minus_p_x = r_x.result.sub(&p.x);
		let r_x_minus_p_x_chip = IntegerSubChip::new(r_x.clone(), self.p.x);
		let r_x_minus_p_x = r_x_minus_p_x_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_x_minus_p_x"),
		)?;

		// m_one_times_r_x_minus_p_x =
		// m_one.result.mul(&r_x_minus_p_x.result);
		let m_one_times_r_x_minus_p_x_chip = IntegerMulChip::new(m_one, r_x_minus_p_x);
		let m_one_times_r_x_minus_p_x = m_one_times_r_x_minus_p_x_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "m_one_times_r_x_minus_p_x"),
		)?;

		// r_y = m_one_times_r_x_minus_p_x.result.sub(&p.y);
		let r_y_chip = IntegerSubChip::new(m_one_times_r_x_minus_p_x, self.p.y);
		let r_y = r_y_chip.synthesize(
			common,
			&config.integer_sub_selector,
			layouter.namespace(|| "r_y"),
		)?;

		let r = AssignedPoint::new(r_x, r_y);
		Ok(r)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccTableSelectConfig {
	/// Constructs config from main circuit.
	main: MainConfig,
}

impl EccTableSelectConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(main: MainConfig) -> Self {
		Self { main }
	}
}

/// Chipset structure for the EccTableSelectChipset.
struct EccTableSelectChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned bit
	bit: AssignedCell<C::Scalar, C::Scalar>,
	// Assigned point p
	p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// Assigned point q
	q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccTableSelectChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc table select chipset.
	pub fn new(
		bit: AssignedCell<C::Scalar, C::Scalar>, p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
		q: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { bit, p, q }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccTableSelectChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccTableSelectConfig;
	type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		let mut selected_x: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		let mut selected_y: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
			[(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			// Select x coordinate limbs
			let select = SelectChipset::new(
				self.bit.clone(),
				self.p.x.limbs[i].clone(),
				self.q.x.limbs[i].clone(),
			);
			selected_x[i] =
				Some(select.synthesize(common, &config.main, layouter.namespace(|| "acc_x"))?);

			// Select y coordinate limbs
			let select = SelectChipset::new(
				self.bit.clone(),
				self.p.y.limbs[i].clone(),
				self.q.y.limbs[i].clone(),
			);
			selected_y[i] =
				Some(select.synthesize(common, &config.main, layouter.namespace(|| "acc_y"))?);
		}

		let selected_point = if assigned_as_bool::<C::Scalar>(self.bit) {
			let selected_x_integer =
				AssignedInteger::new(self.p.x.integer.clone(), selected_x.map(|x| x.unwrap()));
			let selected_y_integer =
				AssignedInteger::new(self.p.y.integer, selected_y.map(|x| x.unwrap()));
			AssignedPoint::new(selected_x_integer, selected_y_integer)
		} else {
			let selected_x_integer =
				AssignedInteger::new(self.q.x.integer.clone(), selected_x.map(|x| x.unwrap()));
			let selected_y_integer =
				AssignedInteger::new(self.q.y.integer, selected_y.map(|x| x.unwrap()));
			AssignedPoint::new(selected_x_integer, selected_y_integer)
		};

		Ok(selected_point)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccMulConfig {
	/// Constructs configs and selector from different circuits.
	ladder: EccUnreducedLadderConfig,
	pub(crate) add: EccAddConfig,
	double: EccDoubleConfig,
	table_select: EccTableSelectConfig,
	bits2num: Selector,
}

impl EccMulConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		ladder: EccUnreducedLadderConfig, add: EccAddConfig, double: EccDoubleConfig,
		table_select: EccTableSelectConfig, bits2num: Selector,
	) -> Self {
		Self { ladder, add, double, table_select, bits2num }
	}
}

/// Chipset structure for the EccMul.
pub struct EccMulChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned point p
	p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// Assigned scalar value
	scalar: AssignedCell<C::Scalar, C::Scalar>,
	// AuxInitial (to_add)
	aux_init: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// AuxFinish (to_sub)
	aux_fin: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccMulChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc mul chipset.
	pub fn new(
		p: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>, scalar: AssignedCell<C::Scalar, C::Scalar>,
		aux_init: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
		aux_fin: AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { p, scalar, aux_init, aux_fin }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccMulChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccMulConfig;
	type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		let aux_init_plus_scalar_chip =
			EccAddChipset::<C, NUM_LIMBS, NUM_BITS, P>::new(self.p.clone(), self.aux_init.clone());
		let aux_init_plus_scalar = aux_init_plus_scalar_chip.synthesize(
			common,
			&config.add,
			layouter.namespace(|| "aux_init_plus_scalar"),
		)?;
		let bits = Bits2NumChip::new(self.scalar);
		let mut bits = bits.synthesize(common, &config.bits2num, layouter.namespace(|| "bits"))?;
		bits.reverse();

		let acc_point_chip = EccTableSelectChipset::new(
			bits[0].clone(),
			aux_init_plus_scalar.clone(),
			self.aux_init.clone(),
		);
		let mut acc_point = acc_point_chip.synthesize(
			common,
			&config.table_select,
			layouter.namespace(|| "acc_select"),
		)?;

		let carry_point_chip = EccTableSelectChipset::new(
			bits[1].clone(),
			aux_init_plus_scalar.clone(),
			self.aux_init.clone(),
		);
		let carry_point = carry_point_chip.synthesize(
			common,
			&config.table_select,
			layouter.namespace(|| "carry_select"),
		)?;

		// To avoid P_0 == P_1
		let acc_double_chip = EccDoubleChipset::new(acc_point);
		acc_point = acc_double_chip.synthesize(
			common,
			&config.double,
			layouter.namespace(|| "acc_double"),
		)?;

		let acc_add_chip = EccAddChipset::new(acc_point, carry_point);
		acc_point =
			acc_add_chip.synthesize(common, &config.add, layouter.namespace(|| "acc_add"))?;

		for bit in bits.iter().skip(2) {
			let carry_point_chip = EccTableSelectChipset::new(
				bit.clone(),
				aux_init_plus_scalar.clone(),
				self.aux_init.clone(),
			);
			let carry_point = carry_point_chip.synthesize(
				common,
				&config.table_select,
				layouter.namespace(|| "carry_select"),
			)?;
			let acc_ladder_chip = EccUnreducedLadderChipset::new(acc_point, carry_point);
			acc_point = acc_ladder_chip.synthesize(
				common,
				&config.ladder,
				layouter.namespace(|| "acc_ladder"),
			)?;
		}

		let acc_add_chip = EccAddChipset::new(acc_point, self.aux_fin);
		acc_point = acc_add_chip.synthesize(
			common,
			&config.add,
			layouter.namespace(|| "acc_add_aux_fin"),
		)?;

		Ok(acc_point)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccBatchedMulConfig {
	/// Constructs configs and selector from different circuits.
	pub(crate) add: EccAddConfig,
	double: EccDoubleConfig,
	bits2num: Selector,
}

impl EccBatchedMulConfig {
	/// Construct a new config
	pub fn new(add: EccAddConfig, double: EccDoubleConfig, bits2num: Selector) -> Self {
		Self { add, double, bits2num }
	}
}

/// Chipset structure for the EccBatchedMul.
pub struct EccBatchedMulChipset<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Assigned points
	points: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
	// Assigned scalar values
	scalars: Vec<AssignedCell<C::Scalar, C::Scalar>>,
	// Window size
	window_size: u32,
	// AuxInitial (to_add)
	aux_inits: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
	// AuxFinish (to_sub)
	aux_fins: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccBatchedMulChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new ecc batched mul scalar chipset.
	pub fn new(
		points: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
		scalars: Vec<AssignedCell<C::Scalar, C::Scalar>>, window_size: u32,
		aux_inits: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
		aux_fins: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
	) -> Self {
		Self { points, scalars, window_size, aux_inits, aux_fins }
	}
}

impl<C: CurveAffine, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<C::Scalar>
	for EccBatchedMulChipset<C, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = EccBatchedMulConfig;
	type Output = Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		let num_of_windows = C::ScalarExt::NUM_BITS / self.window_size;
		let sliding_window_pow2 = 2_u32.pow(self.window_size) as usize;

		let mut multi_bits = Vec::new();
		for i in 0..self.scalars.len() {
			let bits = Bits2NumChip::new(self.scalars[i].clone());
			let mut bits =
				bits.synthesize(common, &config.bits2num, layouter.namespace(|| "bits"))?;
			bits.reverse();
			multi_bits.push(bits);
		}

		let mut table: Vec<Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>> =
			vec![Vec::new(); self.points.len()];

		for i in 0..self.points.len() {
			let mut table_i = self.aux_inits[i].clone();
			for _ in 0..sliding_window_pow2 {
				table[i].push(table_i.clone());

				let add_chip = EccAddChipset::new(table_i, self.points[i].clone());
				table_i = add_chip.synthesize(
					common,
					&config.add,
					layouter.namespace(|| "table_add_points"),
				)?;
			}
		}

		let mut accs: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>> = Vec::new();
		// Initialize accs
		for i in 0..self.points.len() {
			let item = table[i]
				[be_assigned_bits_to_usize(&multi_bits[i][0..self.window_size as usize])]
			.clone();
			accs.push(item);
		}

		for i in 0..self.points.len() {
			for j in 1..num_of_windows {
				for _ in 0..self.window_size {
					let double_chip = EccDoubleChipset::new(accs[i].clone());
					accs[i] = double_chip.synthesize(
						common,
						&config.double,
						layouter.namespace(|| "accs_double"),
					)?;
				}
				let start_bits = (j * self.window_size) as usize;
				let end_bits = ((j + 1) * self.window_size) as usize;
				let item = table[i]
					[be_assigned_bits_to_usize(&multi_bits[i][start_bits..end_bits])]
				.clone();

				let add_chip = EccAddChipset::new(accs[i].clone(), item);
				accs[i] = add_chip.synthesize(
					common,
					&config.add,
					layouter.namespace(|| "accs_add_item"),
				)?;
			}
		}

		// Have to subtract off all the added aux_inits.
		for i in 0..self.points.len() {
			let add_chip = EccAddChipset::new(accs[i].clone(), self.aux_fins[i].clone());
			accs[i] = add_chip.synthesize(
				common,
				&config.add,
				layouter.namespace(|| "accs_add_aux_fins"),
			)?;
		}

		Ok(accs)
	}
}

#[cfg(test)]
mod test {
	use super::{
		native::UnassignedEcPoint, AssignedPoint, EccAddChipset, EccAddConfig,
		EccBatchedMulChipset, EccBatchedMulConfig, EccDoubleChipset, EccDoubleConfig,
		EccMulChipset, EccMulConfig, EccTableSelectConfig, EccUnreducedLadderChipset,
		EccUnreducedLadderConfig,
	};
	use crate::{
		ecc::same_curve::native::EcPoint,
		gadgets::{
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			native::{Integer, UnassignedInteger},
			AssignedInteger, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
			IntegerSubChip,
		},
		params::ecc::{bn254::Bn254Params, EccParams},
		params::rns::bn256::Bn256_4_68,
		Chip, Chipset, CommonConfig, RegionCtx, UnassignedValue,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Fq, Fr, G1Affine},
			CurveAffine,
		},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	use num_bigint::BigUint;
	use rand::thread_rng;
	use std::str::FromStr;

	type W = Fq;
	type N = Fr;
	type C = G1Affine;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Bn256_4_68;
	type EC = Bn254Params;

	#[derive(Clone, Debug)]
	struct TestConfig {
		common: CommonConfig,
		ecc_add: EccAddConfig,
		ecc_double: EccDoubleConfig,
		ecc_ladder: EccUnreducedLadderConfig,
		ecc_mul: EccMulConfig,
		ecc_batched_mul: EccBatchedMulConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<N>) -> Self {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));

			let bits2num_selector = Bits2NumChip::configure(&common, meta);
			let integer_reduce_selector =
				IntegerReduceChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_add_selector =
				IntegerAddChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_sub_selector =
				IntegerSubChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_mul_selector =
				IntegerMulChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_div_selector =
				IntegerDivChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);

			let ecc_add = EccAddConfig::new(
				integer_reduce_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_double = EccDoubleConfig::new(
				integer_reduce_selector, integer_add_selector, integer_sub_selector,
				integer_mul_selector, integer_div_selector,
			);

			let ecc_ladder = EccUnreducedLadderConfig::new(
				integer_add_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_table_select = EccTableSelectConfig::new(main);

			let ecc_mul = EccMulConfig::new(
				ecc_ladder.clone(),
				ecc_add.clone(),
				ecc_double.clone(),
				ecc_table_select,
				bits2num_selector.clone(),
			);

			let ecc_batched_mul =
				EccBatchedMulConfig::new(ecc_add.clone(), ecc_double.clone(), bits2num_selector);

			TestConfig { common, ecc_add, ecc_double, ecc_ladder, ecc_mul, ecc_batched_mul }
		}
	}

	struct IntegerAssigner {
		x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl IntegerAssigner {
		fn new(x: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
			Self { x }
		}
	}

	impl Chipset<N> for IntegerAssigner {
		type Config = ();
		type Output = AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>;

		fn synthesize(
			self, common: &CommonConfig, _: &Self::Config, mut layouter: impl Layouter<N>,
		) -> Result<Self::Output, Error> {
			let assigned_limbs = layouter.assign_region(
				|| "to_add_temp",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let x_limbs = [
						ctx.assign_advice(common.advice[0], self.x.limbs[0])?,
						ctx.assign_advice(common.advice[1], self.x.limbs[1])?,
						ctx.assign_advice(common.advice[2], self.x.limbs[2])?,
						ctx.assign_advice(common.advice[3], self.x.limbs[3])?,
					];

					Ok(x_limbs)
				},
			)?;

			let x_assigned = AssignedInteger::new(self.x.integer, assigned_limbs);
			Ok(x_assigned)
		}
	}

	struct PointAssigner {
		point: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
	}

	impl PointAssigner {
		fn new(point: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
			Self { point }
		}
	}

	impl Chipset<N> for PointAssigner {
		type Config = ();
		type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;

		fn synthesize(
			self, common: &CommonConfig, _: &Self::Config, mut layouter: impl Layouter<N>,
		) -> Result<Self::Output, Error> {
			let x_assigner = IntegerAssigner::new(self.point.x);
			let y_assigner = IntegerAssigner::new(self.point.y);

			let x = x_assigner.synthesize(common, &(), layouter.namespace(|| "x assigner"))?;
			let y = y_assigner.synthesize(common, &(), layouter.namespace(|| "y assigner"))?;

			let point = AssignedPoint::new(x, y);

			Ok(point)
		}
	}

	struct AuxAssigner {
		batch_length: usize,
		window_size: u32,
	}

	impl AuxAssigner {
		fn new(batch_length: usize, window_size: u32) -> Self {
			Self { batch_length, window_size }
		}
	}

	impl Chipset<N> for AuxAssigner {
		type Config = TestConfig;
		type Output = (
			Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
			Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>>,
		);

		fn synthesize(
			self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
		) -> Result<Self::Output, Error> {
			let to_add = Bn254Params::aux_init();
			let to_sub = Bn254Params::make_mul_aux(to_add, self.window_size);

			let to_add_x_coord = to_add.coordinates().unwrap();
			let to_sub_x_coord = to_sub.coordinates().unwrap();

			let to_add_x = to_add_x_coord.x();
			let to_add_y = to_add_x_coord.y();
			let to_sub_x = to_sub_x_coord.x();
			let to_sub_y = to_sub_x_coord.y();

			let to_add_x_int = Integer::from_w(to_add_x.clone());
			let to_add_y_int = Integer::from_w(to_add_y.clone());

			let to_sub_x_int = Integer::from_w(to_sub_x.clone());
			let to_sub_y_int = Integer::from_w(to_sub_y.clone());

			let to_add_point = EcPoint::new(to_add_x_int, to_add_y_int);
			let to_sub_point = EcPoint::new(to_sub_x_int, to_sub_y_int);

			let to_add_assigner = PointAssigner::new(UnassignedEcPoint::from(to_add_point));
			let to_add = to_add_assigner.synthesize(
				common,
				&(),
				layouter.namespace(|| "to_add assigner"),
			)?;
			let to_sub_assigner = PointAssigner::new(UnassignedEcPoint::from(to_sub_point));
			let to_sub = to_sub_assigner.synthesize(
				common,
				&(),
				layouter.namespace(|| "to_sub assigner"),
			)?;

			let mut aux_init = to_add.clone();
			let mut aux_inits: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>> = Vec::new();
			for _ in 0..self.batch_length {
				aux_inits.push(aux_init.clone());
				let double_chip = EccDoubleChipset::new(aux_init);
				aux_init = double_chip.synthesize(
					common,
					&config.ecc_double,
					layouter.namespace(|| "init_double"),
				)?;
			}

			let mut aux_fin = to_sub.clone();
			let mut aux_fins: Vec<AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>> = Vec::new();
			for _ in 0..self.batch_length {
				aux_fins.push(aux_fin.clone());
				let double_chip = EccDoubleChipset::new(aux_fin);
				aux_fin = double_chip.synthesize(
					common,
					&config.ecc_double,
					layouter.namespace(|| "fin_double"),
				)?;
			}

			Ok((aux_inits, aux_fins))
		}
	}

	#[derive(Clone)]
	struct EccAddTestCircuit {
		p: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
		q: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
	}

	impl EccAddTestCircuit {
		fn new(
			p: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>, q: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
		) -> Self {
			Self { p: UnassignedEcPoint::from(p), q: UnassignedEcPoint::from(q) }
		}
	}

	impl Circuit<N> for EccAddTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				p: UnassignedEcPoint::without_witnesses(),
				q: UnassignedEcPoint::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let p_assigner = PointAssigner::new(self.p.clone());
			let p_assigned =
				p_assigner.synthesize(&config.common, &(), layouter.namespace(|| "p assigner"))?;
			let q_assigner = PointAssigner::new(self.q.clone());
			let q_assigned =
				q_assigner.synthesize(&config.common, &(), layouter.namespace(|| "q assigner"))?;
			let chip = EccAddChipset::new(p_assigned, q_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.ecc_add,
				layouter.namespace(|| "ecc_add"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.x.limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					result.y.limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_add_two_points() {
		// Testing add.
		let a_big = BigUint::from_str("23423423525345345").unwrap();
		let b_big = BigUint::from_str("65464575675").unwrap();
		let c_big = BigUint::from_str("23423423423425345647567567568").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let c = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(c_big);
		let p_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(a, b.clone());
		let q_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(b, c);

		let res = p_point.add(&q_point);
		let test_chip = EccAddTestCircuit::new(p_point, q_point);

		let k = 7;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct EccDoubleTestCircuit {
		p: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
	}

	impl EccDoubleTestCircuit {
		fn new(p: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
			Self { p: UnassignedEcPoint::from(p) }
		}
	}

	impl Circuit<N> for EccDoubleTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { p: UnassignedEcPoint::without_witnesses() }
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let p_assigner = PointAssigner::new(self.p.clone());
			let p_assigned =
				p_assigner.synthesize(&config.common, &(), layouter.namespace(|| "p assigner"))?;
			let chip = EccDoubleChipset::new(p_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.ecc_double,
				layouter.namespace(|| "ecc_double"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.x.limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					result.y.limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_double_a_point() {
		// Testing double.
		let a_big = BigUint::from_str("23423423525345345").unwrap();
		let b_big = BigUint::from_str("65464575675").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let p_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(a, b);

		let res = p_point.double();
		let test_chip = EccDoubleTestCircuit::new(p_point);

		let k = 7;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct EccLadderTestCircuit {
		p: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
		q: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
	}

	impl EccLadderTestCircuit {
		fn new(
			p: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>, q: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
		) -> Self {
			Self { p: UnassignedEcPoint::from(p), q: UnassignedEcPoint::from(q) }
		}
	}

	impl Circuit<N> for EccLadderTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				p: UnassignedEcPoint::without_witnesses(),
				q: UnassignedEcPoint::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let p_assigner = PointAssigner::new(self.p.clone());
			let p_assigned =
				p_assigner.synthesize(&config.common, &(), layouter.namespace(|| "p assigner"))?;

			let q_assigner = PointAssigner::new(self.q.clone());
			let q_assigned =
				q_assigner.synthesize(&config.common, &(), layouter.namespace(|| "q assigner"))?;
			let chip = EccUnreducedLadderChipset::new(p_assigned, q_assigned);
			let result = chip.synthesize(
				&config.common,
				&config.ecc_ladder,
				layouter.namespace(|| "ecc_ladder"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.x.limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					result.y.limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_ladder_points() {
		// Testing ladder.
		let a_big = BigUint::from_str("23423423525345345").unwrap();
		let b_big = BigUint::from_str("65464575675").unwrap();
		let c_big = BigUint::from_str("23423423423425345647567567568").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let c = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(c_big);
		let p_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(a, c.clone());
		let q_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(b, c);

		let res = p_point.ladder(&q_point);
		let test_chip = EccLadderTestCircuit::new(p_point, q_point);

		let k = 7;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);
		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct EccMulTestCircuit {
		p: UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
		value: Value<N>,
	}

	impl EccMulTestCircuit {
		fn new(p: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>, value: N) -> Self {
			Self { p: UnassignedEcPoint::from(p), value: Value::known(value) }
		}
	}

	impl Circuit<N> for EccMulTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { p: UnassignedEcPoint::without_witnesses(), value: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let value_assigned = layouter.assign_region(
				|| "scalar_mul_values",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);

					let value = ctx.assign_advice(config.common.advice[0], self.value)?;
					Ok(value)
				},
			)?;

			let aux_assigner = AuxAssigner::new(1, 1);
			let auxes = aux_assigner.synthesize(
				&config.common,
				&config,
				layouter.namespace(|| "aux assigner"),
			)?;
			let to_add = auxes.0[0].clone();
			let to_sub = auxes.1[0].clone();

			let p_assigner = PointAssigner::new(self.p.clone());
			let p_assigned =
				p_assigner.synthesize(&config.common, &(), layouter.namespace(|| "p assigner"))?;

			let chip = EccMulChipset::new(p_assigned, value_assigned, to_add, to_sub);
			let result = chip.synthesize(
				&config.common,
				&config.ecc_mul,
				layouter.namespace(|| "ecc_mul"),
			)?;

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(result.x.limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					result.y.limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn should_mul_scalar_ecc() {
		// Testing ecc mul.
		let rng = &mut thread_rng();
		let scalar = Fr::random(rng);

		let a_big = BigUint::from_str("2342876324689764345467879012938433459867545345").unwrap();
		let b_big = BigUint::from_str("6546457298123794342352534089237495253453455675").unwrap();
		let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(a_big);
		let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(b_big);
		let p_point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(a, b);

		let res = p_point.mul_scalar(scalar);
		let test_chip = EccMulTestCircuit::new(p_point, scalar);

		let k = 15;
		let mut p_ins = Vec::new();
		p_ins.extend(res.x.limbs);
		p_ins.extend(res.y.limbs);

		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct EccBatchedMulTestCircuit {
		points: Vec<UnassignedEcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>>,
		scalars: Vec<Value<N>>,
		window_size: u32,
	}

	impl EccBatchedMulTestCircuit {
		fn new(
			points: Vec<EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>>, scalars: Vec<N>, window_size: u32,
		) -> Self {
			Self {
				points: points.iter().map(|p| UnassignedEcPoint::from(p.clone())).collect(),
				scalars: scalars.iter().map(|s| Value::known(s.clone())).collect(),
				window_size,
			}
		}
	}

	impl Circuit<N> for EccBatchedMulTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				points: self
					.points
					.iter()
					.map(|_| UnassignedEcPoint::without_witnesses())
					.collect(),
				scalars: self.scalars.iter().map(|_| Value::unknown()).collect(),
				window_size: u32::default(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let mut assigned_scalars_dum = [(); 10].map(|_| None);
			layouter.assign_region(
				|| "scalar_mul_values",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					for i in 0..self.scalars.len() {
						let value = ctx.assign_advice(config.common.advice[0], self.scalars[i])?;
						assigned_scalars_dum[i] = Some(value.clone());
						ctx.next();
					}
					Ok(())
				},
			)?;

			let aux_assigner = AuxAssigner::new(self.points.len(), self.window_size);
			let (aux_inits, aux_fins) = aux_assigner.synthesize(
				&config.common,
				&config,
				layouter.namespace(|| "aux assigner"),
			)?;

			let mut assigned_points = Vec::new();
			for point in self.points.clone() {
				let p_assigner = PointAssigner::new(point);
				let p_assigned = p_assigner.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "point assigner"),
				)?;
				assigned_points.push(p_assigned);
			}

			let assigned_scalars = assigned_scalars_dum.map(|x| x.unwrap()).to_vec();

			let chip = EccBatchedMulChipset::new(
				assigned_points, assigned_scalars, self.window_size, aux_inits, aux_fins,
			);
			let results = chip.synthesize(
				&config.common,
				&config.ecc_batched_mul,
				layouter.namespace(|| "ecc_batched_mul"),
			)?;

			for i in 0..results.len() {
				let row_tracker = i * 2 * NUM_LIMBS;
				for j in 0..NUM_LIMBS {
					layouter.constrain_instance(
						results[i].x.limbs[j].cell(),
						config.common.instance,
						row_tracker + j,
					)?;
					layouter.constrain_instance(
						results[i].y.limbs[j].cell(),
						config.common.instance,
						row_tracker + j + NUM_LIMBS,
					)?;
				}
			}

			Ok(())
		}
	}

	#[test]
	fn should_batched_mul_scalar_ecc() {
		// Testing batched ecc mul.
		let rng = &mut thread_rng();
		let mut points_vec = Vec::new();
		let mut scalars_vec = Vec::new();

		for _ in 0..10 {
			scalars_vec.push(Fr::random(rng.clone()));
			let a = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::from_n(Fr::random(rng.clone()));
			let b = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::from_n(Fr::random(rng.clone()));
			let point = EcPoint::<C, NUM_LIMBS, NUM_BITS, P, EC>::new(a, b);
			points_vec.push(point);
		}

		let res = EcPoint::multi_mul_scalar(&points_vec, &scalars_vec);
		let test_chip = EccBatchedMulTestCircuit::new(points_vec, scalars_vec, 2);

		let k = 17;
		let mut p_ins = Vec::new();
		for i in 0..res.len() {
			p_ins.extend(res[i].x.limbs);
			p_ins.extend(res[i].y.limbs);
		}

		let prover = MockProver::run(k, &test_chip, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
