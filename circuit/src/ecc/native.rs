// ADD:
// m = (p_y - q_y) / (p_x - q_x)
// r_x = m^2 - p_x - q_x
// r_y = m * (r_x - p_x) - p_y
// DOUBLE:
// m = (3 * p_x^2) / 2 * p_y
// r_x = m * m - 2 * p_x
// r_y = m * (p_x - r_x) - p_y
// LADDER:
// m_0 = (q_y - p_y) / (q_x - p_x)
// f = m_0 * m_0 - p_x - q_x
// m_1 = m_0 + 2 * p_y / (f - p_x)
// r_x = m_1 * m_1 - p_x - f
// r_y = m_1 * (r_x - p_x) - p_y

use crate::integer::{
	native::{Integer, ReductionWitness},
	rns::RnsParams,
};
use halo2wrong::halo2::arithmetic::{Field, FieldExt};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero};

/// Structure for the EcPoint
#[derive(Clone, Debug)]
pub struct EcPoint<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// X coordinate of the EcPoint
	pub x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Y coordinate of the EcPoint
	pub y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Reduction Witnesses for the EcPoint operations
	pub reduction_witnesses: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Create a new object
	pub fn new(
		x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>, y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, reduction_witnesses: Vec::new() }
	}

	/// Create a new object with x = 0 and y = 0
	pub fn zero() -> Self {
		Self::new(Integer::zero(), Integer::one())
	}

	/// Add one point to another
	pub fn add(&self, other: &Self) -> Self {
		// m = (p_y - q_y) / (p_x - q_x)
		let numerator = self.y.sub(&other.y);
		let denominator = self.x.sub(&other.x);
		let m = numerator.result.div(&denominator.result);
		// r_x = m^2 - p_x - q_x
		let m_squared = m.result.mul(&m.result);
		let m_squared_minus_p_x = m_squared.result.sub(&self.x);
		let r_x = m_squared_minus_p_x.result.sub(&other.x);
		// r_y = m * (r_x - p_x) - p_y
		let r_x_minus_p_x = r_x.result.sub(&self.x);
		let m_times_r_x_minus_p_x = m.result.mul(&r_x_minus_p_x.result);
		let r_y = m_times_r_x_minus_p_x.result.sub(&self.y);

		let reduction_witnesses = vec![
			numerator,
			denominator,
			m,
			m_squared,
			m_squared_minus_p_x,
			r_x.clone(),
			r_x_minus_p_x,
			m_times_r_x_minus_p_x,
			r_y.clone(),
		];

		Self { x: r_x.result, y: r_y.result, reduction_witnesses }
	}

	/// Double the given point
	pub fn double(&self) -> Self {
		// m = (3 * p_x^2) / 2 * p_y
		let double_p_y = self.y.add(&self.y);
		let p_x_square = self.x.mul(&self.x);
		let p_x_square_times_two = p_x_square.result.add(&p_x_square.result);
		let p_x_square_times_three = p_x_square.result.mul(&p_x_square_times_two.result);
		let m = p_x_square_times_three.result.div(&double_p_y.result);

		// r_x = m * m - 2 * p_x
		let double_p_x = self.x.add(&self.x);
		let m_squared = m.result.mul(&m.result);
		let r_x = m_squared.result.sub(&double_p_x.result);

		// r_y = m * (p_x - r_x) - p_y
		let p_x_minus_r_x = self.x.sub(&r_x.result);
		let m_times_p_x_minus_r_x = m.result.mul(&p_x_minus_r_x.result);
		let r_y = m_times_p_x_minus_r_x.result.sub(&self.y);

		let reduction_witnesses = vec![
			double_p_y,
			p_x_square,
			p_x_square_times_two,
			p_x_square_times_three,
			m,
			double_p_x,
			m_squared,
			r_x.clone(),
			p_x_minus_r_x,
			m_times_p_x_minus_r_x,
			r_y.clone(),
		];

		Self { x: r_x.result, y: r_y.result, reduction_witnesses }
	}

	/// Scalar multiplication for given point
	pub fn mul_scalar(&self, val: &BigUint) -> Self {
		let bytes = val.to_bytes_be();

		let mut r = Self::zero();
		let mut exp: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P> = self.clone();
		for i in 0..val.bits() {
			if test_bit(&bytes, i) {
				r = r.add(&exp);
			}
			exp = exp.double();
		}
		r
	}
}

/// Performs bitwise AND to test bits.
pub fn test_bit(b: &[u8], i: usize) -> bool {
	b[i / 8] & (1 << (i % 8)) != 0
}

#[cfg(test)]
mod test {

	#[test]
	fn should_add_two_points() {}

	#[test]
	fn should_double_point() {}
}
