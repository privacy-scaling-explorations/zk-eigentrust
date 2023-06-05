// Ecc implementation over wrong field (using Integer) where both the base field and the scalar field are from the wrong Ecc.

use std::{
	marker::PhantomData,
	ops::{Add, Sub},
};

use halo2::halo2curves::CurveAffine;
use num_bigint::BigUint;
use num_traits::One;

use crate::{
	integer::native::Integer,
	rns::RnsParams,
	utils::{be_bits_to_usize, big_to_fe, fe_to_big, to_bits},
	FieldExt,
};

use halo2::arithmetic::Field;
use halo2::halo2curves::ff::PrimeField;

/// Structure for the EcPoint
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EcPoint<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, Q>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	<C as CurveAffine>::Base: FieldExt,
	Q: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	<C as CurveAffine>::ScalarExt: FieldExt,
{
	/// X coordinate of the EcPoint
	pub x: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
	/// Y coordinate of the EcPoint
	pub y: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
	phantom: PhantomData<Q>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, Q>
	EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	<C as CurveAffine>::Base: FieldExt,
	Q: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	<C as CurveAffine>::ScalarExt: FieldExt,
{
	/// Create a new object
	pub fn new(
		x: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
		y: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, phantom: PhantomData }
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

	/// Make aux_fin when sliding window is > 1.
	pub fn make_mul_aux_sliding_window(aux_to_add: Self, window_size: usize) -> Self {
		assert!(window_size > 0);

		let n = C::ScalarExt::NUM_BITS as usize;
		let number_of_selectors = n / window_size;
		let leftover = n % window_size;
		let mut k0 = BigUint::one();
		let one = BigUint::one();
		for i in 0..number_of_selectors {
			k0 |= &one << (i * window_size);
		}

		if (leftover != 0) {
			k0 = k0 << leftover;
			k0 = k0.add(&one);
		}

		let factor = Integer::new(fe_to_big(
			C::ScalarExt::ZERO.sub(big_to_fe::<C::ScalarExt>(k0)),
		));

		let to_sub = aux_to_add.mul_scalar(factor);
		to_sub
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

		Self { x: r_x.result, y: r_y.result, phantom: PhantomData }
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

		Self { x: r_x.result, y: r_y.result, phantom: PhantomData }
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

		Self { x: r_x.result, y: r_y.result, phantom: PhantomData }
	}

	/// Scalar multiplication for given point with using ladder
	pub fn mul_scalar(&self, scalar: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, Q>) -> Self {
		let aux_init = Self::to_add();
		let exp: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q> = self.clone();
		// Converts given input to its bit by Scalar Field's bit size
		let mut bits = to_bits(big_to_fe::<C::Scalar>(scalar.value()).to_repr().as_ref());
		bits = bits[..C::ScalarExt::NUM_BITS as usize].to_vec();
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
	pub fn multi_mul_scalar(
		points: &[Self], scalars: &[Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, Q>],
		sliding_window_usize: usize,
	) -> Vec<Self> {
		// AuxGens from article.
		let mut aux_inits: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>> = vec![];
		let mut aux_init = Self::to_sub();
		for _ in 0..points.len() {
			aux_inits.push(aux_init.clone());
			aux_init = aux_init.double();
		}

		let mut num_of_windows: Vec<usize> = vec![];

		let exps: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>> = points.to_vec();
		let bits: Vec<Vec<bool>> = scalars
			.iter()
			.map(|scalar| {
				let mut scalar_as_bits =
					to_bits(big_to_fe::<C::Scalar>(scalar.value()).to_repr().as_ref());
				scalar_as_bits = scalar_as_bits[..C::ScalarExt::NUM_BITS as usize].to_vec();
				num_of_windows.push(scalar_as_bits.len() / sliding_window_usize);
				scalar_as_bits.reverse();
				scalar_as_bits
			})
			.collect();

		let sliding_window_pow2 = 2_u32.pow(sliding_window_usize.try_into().unwrap()) as usize;

		// Construct selector table for each mul
		let mut table: Vec<Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>>> = vec![];
		for i in 0..exps.len() {
			table.push(vec![]);
			let mut table_i = aux_inits[i].clone();
			for _ in 0..sliding_window_pow2 {
				table[i].push(table_i.clone());
				table_i = table_i.add(&exps[i]);
			}
		}

		let mut accs: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>> = vec![];

		// Initialize accs
		for i in 0..exps.len() {
			if num_of_windows[i] > 0 {
				let item = Self::select_vec(
					be_bits_to_usize(&bits[i][0..sliding_window_usize]),
					table[i].clone(),
				);
				accs.push(item);
			} else {
				let item = Self::select_vec(be_bits_to_usize(&bits[i][0..]), table[i].clone());
				accs.push(item);
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
							let item = Self::select_vec(
								be_bits_to_usize(&leftover_bits),
								table[i].clone(),
							);
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

		let mut aux_fins: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, Q>> = vec![];
		let aux_init = Self::to_sub();
		let mut aux_fin = Self::make_mul_aux_sliding_window(aux_init, sliding_window_usize);
		for i in 0..points.len() {
			aux_fins.push(aux_fin.clone());
			aux_fin = aux_fin.double();
		}

		// Have to subtract off all the added aux_inits.
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
