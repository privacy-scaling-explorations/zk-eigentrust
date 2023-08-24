/// Params for bn254
pub mod bn254;
/// Params for secp256k1
pub mod secp256k1;

use crate::utils::big_to_fe;
use crate::FieldExt;
use halo2::halo2curves::ff::PrimeField;
use halo2::halo2curves::group::Curve;
use halo2::halo2curves::CurveAffine;
use num_bigint::BigUint;
use num_traits::One;
use std::fmt::Debug;

/// Params for Ecc operations
pub trait EccParams<C: CurveAffine>: Clone + Default + Debug + PartialEq {
	/// Sliding window size
	fn window_size() -> u32;

	/// Aux init point
	fn aux_init() -> C;

	/// Make aux_fin when sliding window is > 1.
	fn make_mul_aux(aux_to_add: C, window_size: u32) -> C
	where
		C::Scalar: FieldExt,
	{
		assert!(C::Scalar::NUM_BITS % window_size == 0);
		assert!(window_size > 0);

		let n = C::Scalar::NUM_BITS;
		let number_of_selectors = n / window_size;
		let mut k0 = BigUint::one();
		let one = BigUint::one();
		for i in 0..number_of_selectors {
			k0 |= &one << (i * window_size);
		}

		(-aux_to_add * big_to_fe::<C::Scalar>(k0)).to_affine()
	}
}
