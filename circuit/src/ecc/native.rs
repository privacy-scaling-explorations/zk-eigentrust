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

use std::io::empty;

use crate::{
	integer::native::Integer,
	rns::RnsParams,
	utils::{be_bits_to_usize, big_to_fe, to_bits},
	FieldExt,
};

use halo2::{
	arithmetic::Field,
	halo2curves::{
		bn256::{Fq, Fr, G1Affine},
		group::Curve,
	},
};
use num_bigint::BigUint;

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

	/// Selection function for the table
	fn select(bit: bool, table: [Self; 2]) -> Self {
		if bit {
			table[1].clone()
		} else {
			table[0].clone()
		}
	}

	/// Selection function for the table
	fn select_vec(index: usize, table: Vec<Self>) -> Self {
		return table[index].clone();
	}

	/// AuxInit
	pub fn to_add() -> Self {
		let x_limbs = P::to_add_x();
		let y_limbs = P::to_add_y();
		Self::new(Integer::from_limbs(x_limbs), Integer::from_limbs(y_limbs))
	}

	/// AuxFin
	pub fn to_sub() -> Self {
		let x_limbs = P::to_sub_x();
		let y_limbs = P::to_sub_y();
		Self::new(Integer::from_limbs(x_limbs), Integer::from_limbs(y_limbs))
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

	/// Scalar multiplication for given point with using ladder
	pub fn mul_scalar<S: FieldExt>(&self, scalar: S) -> Self {
		let aux_init = Self::to_add();
		let exp: EcPoint<W, N, NUM_LIMBS, NUM_BITS, P> = self.clone();
		// Converts given input to its bit by Scalar Field's bit size
		let mut bits = to_bits(scalar.to_repr().as_ref());
		bits = bits[..S::NUM_BITS as usize].to_vec();
		bits.reverse();

		let table = [aux_init.clone(), exp.add(&aux_init)];
		let mut acc = Self::select(bits[0], table.clone());

		// To avoid P_0 == P_1
		acc = acc.double();
		acc = acc.add(&Self::select(bits[1], table.clone()));

		// Double and Add operation with ladder
		for bit in &bits[2..] {
			let item = Self::select(*bit, table.clone());
			acc = acc.ladder(&item);
		}

		let aux_fin = Self::to_sub();
		acc = acc.add(&aux_fin);

		acc
	}

	/// Multi-multiplication for given points using sliding window.
	pub fn multi_mul_scalar<S: FieldExt>(
		points: &[Self], scalars: &[S], sliding_window_usize: usize,
	) -> Vec<Self> {
		// AuxGens from article.
		let mut aux_inits: Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>> = vec![];
		let mut aux_init = Self::to_add();
		for _ in 0..points.len() {
			aux_inits.push(aux_init.clone());
			aux_init = aux_init.double();
		}

		let mut num_of_windows: Vec<usize> = vec![];

		let exps: Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>> = points.to_vec();
		let bits: Vec<Vec<bool>> = scalars
			.iter()
			.map(|scalar| {
				let mut scalar_as_bits = to_bits(scalar.to_repr().as_ref());
				scalar_as_bits = scalar_as_bits[..S::NUM_BITS as usize].to_vec();
				num_of_windows.push(scalar_as_bits.len() / sliding_window_usize);
				scalar_as_bits.reverse();
				scalar_as_bits
			})
			.collect();

		let sliding_window_pow2 = 2_u32.pow(sliding_window_usize.try_into().unwrap()) as usize;

		// Construct selector table for each mul
		let mut table: Vec<Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>>> = vec![];
		for i in 0..exps.len() {
			table.push(vec![]);
			let mut table_i = aux_inits[i].clone();
			for _ in 0..sliding_window_pow2 {
				table[i].push(table_i.clone());
				table_i = table_i.add(&exps[i]);
			}
		}

		let mut accs: Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>> = vec![];

		// Initialize accs
		for i in 0..exps.len() {
			if num_of_windows[i] > 0 {
				accs.push(Self::select_vec(
					be_bits_to_usize(&bits[i][0..sliding_window_usize]),
					table[i].clone(),
				));
			} else {
				println!("reached here 1 {}", i);
				accs.push(Self::select_vec(
					be_bits_to_usize(&bits[i][0..]),
					table[i].clone(),
				));
			}
		}

		for i in 0..exps.len() {
			if num_of_windows[i] > 0 {
				for j in 1..(num_of_windows[i] + 1) {
					if j == num_of_windows[i] {
						let leftover_bits = &bits[i][(j * sliding_window_usize)..];
						if leftover_bits.len() > 0 {
							for _ in 0..leftover_bits.len() {
								accs[i] = accs[i].double();
							}
							let item = Self::select_vec(be_bits_to_usize(&leftover_bits), table[i].clone());
							accs[i] = accs[i].add(&item);
						}
					} else {
						for _ in 0..sliding_window_usize {
							accs[i] = accs[i].double();
						}
						let item = Self::select_vec(
							be_bits_to_usize(
								&bits[i]
									[(j * sliding_window_usize)..((j + 1) * sliding_window_usize)],
							),
							table[i].clone(),
						);
						accs[i] = accs[i].add(&item);
					}
				}
			}
		}

		// Have to subtract off all the added aux_inits.
		let mut aux_fins: Vec<EcPoint<W, N, NUM_LIMBS, NUM_BITS, P>> = vec![];
		let mut aux_fin = Self::to_sub();
		for i in 0..points.len() {
			aux_fins.push(aux_fin.clone());
			aux_fin = aux_fin.double();
		}
		for i in 0..exps.len() {
			accs[i] = accs[i].add(&aux_fins[i]);
		}

		accs
	}

	/// Check if two points are equal
	pub fn is_eq(&self, other: &Self) -> bool {
		self.x.is_eq(&other.x) && self.y.is_eq(&other.y)
	}
}

#[cfg(test)]
mod test {
	use core::num;

use super::EcPoint;
	use crate::{
		integer::native::Integer,
		rns::bn256::Bn256_4_68,
		utils::{big_to_fe, fe_to_big},
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
		// ECC Add test
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
		// ECC Double test
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
		// ECC Ladder test
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
		// ECC Mul Scalar with Ladder test
		let rng = &mut thread_rng();
		let a = G1Affine::random(rng.clone());
		let scalar = Fr::random(rng);
		let c = (a * scalar).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);

		let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);
		let a_w = EcPoint::new(a_x_w, a_y_w);

		let c_w = a_w.mul_scalar(scalar);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_batch_mul_scalar() {
		// ECC Mul Scalar with Ladder test
		let num_of_points = 10;
		let rng = &mut thread_rng();
		let mut points_vec = vec![];
		let mut scalars_vec = vec![];
		let mut results_vec = vec![];
		for i in 0..num_of_points {
			let a = G1Affine::random(rng.clone());
			let scalar = Fr::random(rng.clone());
			scalars_vec.push(scalar);
			let c = (a * scalar).to_affine();
			results_vec.push(c);
			let a_x_bn = fe_to_big(a.x);
			let a_y_bn = fe_to_big(a.y);
			let a_x_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_x_bn);
			let a_y_w = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_y_bn);
			let a_w = EcPoint::new(a_x_w, a_y_w);
			points_vec.push(a_w.clone());
		}
		let batch_mul_results_vec = EcPoint::multi_mul_scalar(
			&points_vec,
			&scalars_vec,
			4,
		);
		for i in 0..num_of_points {
			println!("i is {}", i);
			assert_eq!(results_vec[i].x, big_to_fe(batch_mul_results_vec[i].x.value()));
			assert_eq!(results_vec[i].y, big_to_fe(batch_mul_results_vec[i].y.value()));
		}
	}
}
