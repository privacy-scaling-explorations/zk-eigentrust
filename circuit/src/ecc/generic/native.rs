// Ecc implementation over wrong field (using Integer) where both the base field and the scalar field are from the wrong Ecc.

use crate::{
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	utils::{be_bits_to_usize, big_to_fe, to_bits},
	FieldExt,
};
use halo2::halo2curves::ff::PrimeField;
use halo2::halo2curves::CurveAffine;
use std::marker::PhantomData;

/// Structure for the EcPoint
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EcPoint<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	<C as CurveAffine>::Base: FieldExt,
	<C as CurveAffine>::ScalarExt: FieldExt,
{
	/// X coordinate of the EcPoint
	pub x: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
	/// Y coordinate of the EcPoint
	pub y: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,

	_ec: PhantomData<EC>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	<C as CurveAffine>::Base: FieldExt,
	<C as CurveAffine>::ScalarExt: FieldExt,
{
	/// Create a new object
	pub fn new(
		x: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
		y: Integer<C::Base, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { x, y, _ec: PhantomData }
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

	/// Aux points
	pub fn aux(window_size: u32) -> (Self, Self) {
		let to_add = EC::aux_init();
		let to_sub = EC::make_mul_aux(to_add, window_size);

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

		let to_add = Self::new(to_add_x_int, to_add_y_int);
		let to_sub = Self::new(to_sub_x_int, to_sub_y_int);
		(to_add, to_sub)
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

		Self { x: r_x.result, y: r_y.result, _ec: PhantomData }
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

		Self { x: r_x.result, y: r_y.result, _ec: PhantomData }
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

		Self { x: r_x.result, y: r_y.result, _ec: PhantomData }
	}

	/// Scalar multiplication for given point with using ladder
	pub fn mul_scalar(&self, scalar: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		let (aux_init, aux_fin) = Self::aux(1);

		let exp = self.clone();
		// Converts given input to its bit by Scalar Field's bit size
		let mut bits = to_bits(big_to_fe::<C::ScalarExt>(scalar.value()).to_repr().as_ref());
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

		acc = acc.add(&aux_fin);
		acc
	}

	/// Multi-multiplication for given points using sliding window.
	pub fn multi_mul_scalar(
		points: &[Self], scalars: &[Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>],
	) -> Vec<Self> {
		let sliding_window_size = EC::window_size();
		// AuxGens from article.
		let (mut aux_init, mut aux_fin) = Self::aux(EC::window_size());

		let mut aux_inits: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>> = Vec::new();
		for _ in 0..points.len() {
			aux_inits.push(aux_init.clone());
			aux_init = aux_init.double();
		}

		let mut aux_fins: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>> = Vec::new();
		for _ in 0..points.len() {
			aux_fins.push(aux_fin.clone());
			aux_fin = aux_fin.double();
		}

		let num_of_windows = C::ScalarExt::NUM_BITS / sliding_window_size;

		let exps: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>> = points.to_vec();
		let bits: Vec<Vec<bool>> = scalars
			.iter()
			.map(|scalar| {
				let mut scalar_as_bits =
					to_bits(big_to_fe::<C::ScalarExt>(scalar.value()).to_repr().as_ref());
				scalar_as_bits = scalar_as_bits[..C::ScalarExt::NUM_BITS as usize].to_vec();
				scalar_as_bits.reverse();
				scalar_as_bits
			})
			.collect();

		let sliding_window_pow2 = 2_u32.pow(sliding_window_size) as usize;

		// Construct selector table for each mul
		let mut table: Vec<Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>>> =
			vec![Vec::new(); exps.len()];
		for i in 0..exps.len() {
			let mut table_i = aux_inits[i].clone();
			for _ in 0..sliding_window_pow2 {
				table[i].push(table_i.clone());
				table_i = table_i.add(&exps[i]);
			}
		}

		let mut accs: Vec<EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>> = Vec::new();

		// Initialize accs
		for i in 0..exps.len() {
			let item = Self::select_vec(
				be_bits_to_usize(&bits[i][0..sliding_window_size as usize]),
				table[i].clone(),
			);
			accs.push(item);
		}

		for i in 0..exps.len() {
			for j in 1..num_of_windows {
				for _ in 0..sliding_window_size {
					accs[i] = accs[i].double();
				}
				let start_bits = (j * sliding_window_size) as usize;
				let end_bits = ((j + 1) * sliding_window_size) as usize;
				let item = Self::select_vec(
					be_bits_to_usize(&bits[i][start_bits..end_bits]),
					table[i].clone(),
				);
				accs[i] = accs[i].add(&item);
			}
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

#[cfg(test)]
mod test {
	use super::EcPoint;
	use crate::{
		integer::native::Integer,
		params::{ecc::secp256k1::Secp256k1Params, rns::secp256k1::Secp256k1_4_68},
		utils::{big_to_fe, fe_to_big},
	};
	use halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::Fr,
			group::Curve,
			secp256k1::{Fp, Fq, Secp256k1Affine},
		},
	};
	use rand::thread_rng;

	#[test]
	fn should_add_two_points() {
		// ECC Add test
		let rng = &mut thread_rng();

		let a = Secp256k1Affine::random(rng.clone());
		let b = Secp256k1Affine::random(rng.clone());
		let c = (a + b).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);
		let b_x_bn = fe_to_big(b.x);
		let b_y_bn = fe_to_big(b.y);

		let a_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_y_bn);
		let b_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(b_x_bn);
		let b_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(b_y_bn);

		let a_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
			EcPoint::new(a_x_w, a_y_w);
		let b_w = EcPoint::new(b_x_w, b_y_w);
		let c_w = a_w.add(&b_w);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_double_point() {
		// ECC Double test
		let rng = &mut thread_rng();

		let a = Secp256k1Affine::random(rng.clone());
		let c = (a + a).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);

		let a_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_y_bn);

		let a_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
			EcPoint::new(a_x_w, a_y_w);
		let c_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, _> = a_w.double();

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_ladder() {
		// ECC Ladder test
		let rng = &mut thread_rng();

		let a = Secp256k1Affine::random(rng.clone());
		let b = Secp256k1Affine::random(rng.clone());
		let c = (a + a + b).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);
		let b_x_bn = fe_to_big(b.x);
		let b_y_bn = fe_to_big(b.y);

		let a_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_y_bn);
		let b_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(b_x_bn);
		let b_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(b_y_bn);

		let a_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
			EcPoint::new(a_x_w, a_y_w);
		let b_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
			EcPoint::new(b_x_w, b_y_w);
		let c_w = a_w.ladder(&b_w);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_mul_scalar() {
		// ECC Mul Scalar with Ladder test
		let rng = &mut thread_rng();
		let a = Secp256k1Affine::random(rng.clone());
		let scalar = Fq::random(rng);
		let c = (a * scalar).to_affine();

		let a_x_bn = fe_to_big(a.x);
		let a_y_bn = fe_to_big(a.y);

		let a_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_x_bn);
		let a_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_y_bn);
		let a_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
			EcPoint::new(a_x_w, a_y_w);
		let scalar_as_integer = Integer::from_w(scalar);
		let c_w = a_w.mul_scalar(scalar_as_integer);

		assert_eq!(c.x, big_to_fe(c_w.x.value()));
		assert_eq!(c.y, big_to_fe(c_w.y.value()));
	}

	#[test]
	fn should_batch_mul_scalar() {
		// ECC Mul Scalar with Ladder test
		let num_of_points = 10;
		let rng = &mut thread_rng();

		let mut points_vec = Vec::new();
		let mut scalars_vec = Vec::new();
		let mut results_vec = Vec::new();
		for _ in 0..num_of_points {
			let a = Secp256k1Affine::random(rng.clone());
			let scalar = Fq::random(rng.clone());
			scalars_vec.push(Integer::from_w(scalar));

			let c = (a * scalar).to_affine();
			results_vec.push(c);

			let a_x_bn = fe_to_big(a.x);
			let a_y_bn = fe_to_big(a.y);

			let a_x_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_x_bn);
			let a_y_w = Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::new(a_y_bn);
			let a_w: EcPoint<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params> =
				EcPoint::new(a_x_w, a_y_w);
			points_vec.push(a_w.clone());
		}

		let batch_mul_results_vec = EcPoint::multi_mul_scalar(&points_vec, &scalars_vec);
		for i in 0..num_of_points {
			assert_eq!(
				results_vec[i].x,
				big_to_fe(batch_mul_results_vec[i].x.value())
			);
			assert_eq!(
				results_vec[i].y,
				big_to_fe(batch_mul_results_vec[i].y.value())
			);
		}
	}
}
