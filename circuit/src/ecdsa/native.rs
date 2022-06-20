use ecc::maingate::{big_to_fe, fe_to_big};
use halo2wrong::{
	curves::group::Curve,
	halo2::arithmetic::{CurveAffine, Field, FieldExt},
};
use rand::Rng;
use std::io::Error;

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct SigData<F: FieldExt> {
	pub r: F,
	pub s: F,
	pub m_hash: F,
}

impl<F: FieldExt> SigData<F> {
	pub fn empty() -> Self {
		Self {
			r: F::zero(),
			s: F::zero(),
			m_hash: F::zero(),
		}
	}
}

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
	let x_big = fe_to_big(x);
	big_to_fe(x_big)
}

#[derive(Default, Clone, Copy)]
pub struct Keypair<E: CurveAffine> {
	sk: E::ScalarExt,
	pk: E,
}

impl<E: CurveAffine> Keypair<E> {
	pub fn empty() -> Self {
		Self {
			sk: E::ScalarExt::zero(),
			pk: E::default(),
		}
	}
}

impl<E: CurveAffine> Keypair<E> {
	pub fn new<R: Rng>(r: &mut R) -> Self {
		let sk = E::ScalarExt::random(r);
		let g = E::generator();
		// Generate a key pair
		let pk = (g * sk).to_affine();
		Self { sk, pk }
	}

	pub fn from_pair(sk: E::ScalarExt, pk: E) -> Self {
		Self { sk, pk }
	}

	pub fn public(&self) -> &E {
		&self.pk
	}

	pub fn secret(&self) -> &E::ScalarExt {
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

	let sig_data = SigData { r, s, m_hash };
	Ok(sig_data)
}

pub fn verify_signature<E: CurveAffine>(sig_data: &SigData<E::ScalarExt>, pk: &E) -> bool {
	let s_inv = sig_data.s.invert().unwrap();
	let u1 = s_inv * sig_data.m_hash;
	let u2 = s_inv * sig_data.r;
	let e_gen = E::generator();
	let g1 = e_gen * u1;
	let g2 = *pk * u2;
	let q_coordinates = (g1 + g2).to_affine().coordinates().unwrap();
	let q_x = q_coordinates.x();
	let q_x_reduced_in_r = mod_n::<E>(*q_x);

	sig_data.r == q_x_reduced_in_r
}
