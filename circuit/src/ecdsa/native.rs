use ecc::maingate::{big_to_fe, fe_to_big};
use halo2wrong::{
	curves::group::Curve,
	halo2::arithmetic::{CurveAffine, Field, FieldExt},
};
use rand::Rng;
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

#[derive(Default, Clone, Copy)]
pub struct Keypair<E: CurveAffine> {
	sk: E::ScalarExt,
	pk: E
}

impl<E: CurveAffine> Keypair<E> {
	pub fn new<R: Rng>(r: &mut R) -> Self {
		let sk = E::ScalarExt::random(r);
		let g = E::generator();
		// Generate a key pair
		let pk = (g * sk).to_affine();
		Self { sk, pk }
	}

	pub fn public_key(&self) -> &E {
		&self.pk
	}

	pub fn sk(&self) -> &E::ScalarExt {
		&self.sk
	}
}

pub fn generate_signature<E: CurveAffine, R: Rng>(
	pair: Keypair<E>,
	m_hash: E::ScalarExt,
	r: &mut R,
) -> Result<SigData<E::ScalarExt>, Error> {
	// Draw randomness
	let k = E::ScalarExt::random(r);
	let k_inv = k.invert().unwrap();
	
	let g = E::generator();
	// Calculate `r`
	let r_point = (g * k).to_affine().coordinates().unwrap();
	let x = r_point.x();
	let r = mod_n::<E>(*x);

	// Calculate `s`
	let s = k_inv * (m_hash + (r * pair.sk));

	let sig_data = SigData { r, s };
	Ok(sig_data)
}
