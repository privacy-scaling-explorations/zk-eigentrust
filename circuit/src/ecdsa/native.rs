use ecc::maingate::{big_to_fe, fe_to_big};
use halo2wrong::{
	curves::group::Curve,
	halo2::arithmetic::{CurveAffine, Field, FieldExt},
};
use rand::thread_rng;
use std::io::Error;

#[derive(Default, Clone, Copy)]
pub struct SigData<F: FieldExt> {
	pub r: F,
	pub s: F,
}

impl<F: FieldExt> SigData<F> {
	pub fn from_repr(r: F::Repr, s: F::Repr) -> Self {
		let r = F::from_repr(r).unwrap();
		let s = F::from_repr(s).unwrap();

		Self { r, s }
	}
}

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
	let x_big = fe_to_big(x);
	big_to_fe(x_big)
}

pub fn generate_signature<E: CurveAffine>(
	sk: E::ScalarExt,
	m_hash: E::ScalarExt,
) -> Result<(SigData<E::ScalarExt>, E), Error> {
	let mut rng = thread_rng();

	let g = E::generator();

	// Generate a key pair
	let pk = (g * sk).to_affine();

	// Draw arandomness
	let k = E::ScalarExt::random(&mut rng);
	let k_inv = k.invert().unwrap();

	// Calculate `r`
	let r_point = (g * k).to_affine().coordinates().unwrap();
	let x = r_point.x();
	let r = mod_n::<E>(*x);

	// Calculate `s`
	let s = k_inv * (m_hash + (r * sk));

	let sig_data = SigData { r, s };
	Ok((sig_data, pk))
}
