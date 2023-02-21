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

use crate::integer::{native::Integer, rns::RnsParams};
use halo2::arithmetic::FieldExt;

/// Structure for the EcPoint
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EcPoint<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// X coordinate of the EcPoint
	pub x: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Y coordinate of the EcPoint
	pub y: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
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
		Self { x, y }
	}

	/// Create a new object with x = 0 and y = 1
	pub fn zero() -> Self {
		Self::new(Integer::zero(), Integer::one())
	}

	/// Create a new object with x = 1 and y = 1
	pub fn one() -> Self {
		Self::new(Integer::one(), Integer::one())
	}

	/// Add one point to another
	pub fn add(&self, other: &Self) -> Self {
		// m = (q_y - p_y) / (q_x - p_x)
		let numerator = other.y.sub(&self.y);
		let denominator = other.x.sub(&self.x);
		let m = numerator.result.div(&denominator.result);
		// r_x = m^2 - p_x - q_x
		let m_squared = m.result.mul(&m.result);
		let m_squared_minus_p_x = m_squared.result.sub(&self.x);
		let r_x = m_squared_minus_p_x.result.sub(&other.x);
		// r_y = m * (p_x - r_x) - p_y
		let r_x_minus_p_x = self.x.sub(&r_x.result);
		let m_times_r_x_minus_p_x = m.result.mul(&r_x_minus_p_x.result);
		let r_y = m_times_r_x_minus_p_x.result.sub(&self.y);

		Self { x: r_x.result, y: r_y.result }
	}

	/// Double the given point
	pub fn double(&self) -> Self {
		// m = (3 * p_x^2) / 2 * p_y
		let double_p_y = self.y.add(&self.y);
		let p_x_square = self.x.mul(&self.x);
		let p_x_square_times_two = p_x_square.result.add(&p_x_square.result);
		let p_x_square_times_three = p_x_square.result.add(&p_x_square_times_two.result);
		let m = p_x_square_times_three.result.div(&double_p_y.result);

		// r_x = m * m - 2 * p_x
		let double_p_x = self.x.add(&self.x);
		let m_squared = m.result.mul(&m.result);
		let r_x = m_squared.result.sub(&double_p_x.result);

		// r_y = m * (p_x - r_x) - p_y
		let p_x_minus_r_x = self.x.sub(&r_x.result);
		let m_times_p_x_minus_r_x = m.result.mul(&p_x_minus_r_x.result);
		let r_y = m_times_p_x_minus_r_x.result.sub(&self.y);

		Self { x: r_x.result, y: r_y.result }
	}

	/// Given 2 `AssignedPoint` `P` and `Q` efficiently computes `2*P + Q`
	pub fn ladder(&self, other: &Self) -> Self {
		// (P + Q) + P
		// P is to_double (x_1, y_1)
		// Q is to_add (x_2, y_2)

		// m_0 = (y_2 - y_1) / (x_2 - x_1)
		let numerator = other.y.sub(&self.y);
		let denominator = other.x.sub(&self.x);
		let m_zero = numerator.result.div(&denominator.result);

		// x_3 = m_0 * m_0 - x_1 - x_2
		let m_zero_squared = m_zero.result.mul(&m_zero.result);
		let m_zero_squared_minus_p_x = m_zero_squared.result.sub(&self.x);
		let x_three = m_zero_squared_minus_p_x.result.sub(&other.x);

		// m_1 = m_0 + 2 * y_1 / (x_3 - x_1)
		let double_p_y = self.y.add(&self.y);
		let denom_m_one = x_three.result.sub(&self.x);
		let div_res = double_p_y.result.div(&denom_m_one.result);
		let m_one = m_zero.result.add(&div_res.result);

		// x_4 = m_1 * m_1 - x_1 - x_3
		let m_one_squared = m_one.result.mul(&m_one.result);
		let m_one_squared_minus_r_x = m_one_squared.result.sub(&x_three.result);
		let r_x = m_one_squared_minus_r_x.result.sub(&self.x);

		// y_4 = m_1 * (x_4 - x_1) - y_1
		let r_x_minus_p_x = r_x.result.sub(&self.x);
		let m_one_times_r_x_minus_p_x = m_one.result.mul(&r_x_minus_p_x.result);
		let r_y = m_one_times_r_x_minus_p_x.result.sub(&self.y);

		Self { x: r_x.result, y: r_y.result }
	}

	/// Scalar multiplication for given point
	pub fn mul_scalar(&self, le_bytes: [u8; 32]) -> Self {
		let mut r = Self::zero();
		let mut exp: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P> = self.clone();

		// Big Endian vs Little Endian
		let bits = le_bytes.map(|byte| {
			let mut byte_bits = [false; 8];
			for i in (0..8).rev() {
				byte_bits[i] = (byte >> i) & 1u8 != 0
			}
			byte_bits
		});
		let mut flag = true;
		// Double and Add operation
		for bit in bits.flatten() {
			if *bit {
				// Addition operation with zero is not working for the add() function because
				// zero + random value breaks
				// the algorithm. (Two operands must be distinct and neither of them can be
				// point at infinity. Otherwise the function returns an erroneous point.) So,
				// just for the first iteration value assigned manually.
				if flag {
					r = exp.clone();
					flag = false;
				} else {
					r = r.add(&exp.clone());
				}
			}
			exp = exp.double();
		}
		r
	}

	/// Check if two points are equal
	pub fn is_eq(&self, other: &Self) -> bool {
		self.x.is_eq(&other.x) && self.y.is_eq(&other.y)
	}
}

#[cfg(test)]
mod test {
	use super::EcPoint;
	use crate::integer::{
		native::Integer,
		rns::{big_to_fe, fe_to_big, Bn256_4_68},
	};
	use halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::{Fq, Fr, G1Affine},
			group::Curve,
		},
	};
	use rand::thread_rng;

	#[test]
	fn should_add_two_points() {
		let rng = &mut thread_rng();

		let a = G1Affine::random(rng.clone());
		let b = G1Affine::random(rng.clone());
		let c = (a + b).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);
		let b_x_bn = fe_to_big(b.x);
		let b_y_bn = fe_to_big(b.y);

		let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);
		let b_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_x_bn);
		let b_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_y_bn);

		let a_w = EcPoint::new(a_x_w, a_y_w);
		let b_w = EcPoint::new(b_x_w, b_y_w);
		let c_w = a_w.add(&b_w);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_double_point() {
		let rng = &mut thread_rng();

		let a = G1Affine::random(rng.clone());
		let c = (a + a).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);

		let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);

		let a_w = EcPoint::new(a_x_w, a_y_w);
		let c_w = a_w.double();

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_ladder() {
		let rng = &mut thread_rng();

		let a = G1Affine::random(rng.clone());
		let b = G1Affine::random(rng.clone());
		let c = (a + a + b).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);
		let b_x_bn = fe_to_big(b.x);
		let b_y_bn = fe_to_big(b.y);

		let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);
		let b_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_x_bn);
		let b_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_y_bn);

		let a_w = EcPoint::new(a_x_w, a_y_w);
		let b_w = EcPoint::new(b_x_w, b_y_w);
		let c_w = a_w.ladder(&b_w);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_mul_scalar() {
		let rng = &mut thread_rng();
		let a = G1Affine::random(rng.clone());
		let scalar = Fr::random(rng);
		let c = (a * scalar).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);

		let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);

		let a_w = EcPoint::new(a_x_w, a_y_w);
		let c_w = a_w.mul_scalar(scalar.to_bytes());

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}
}
