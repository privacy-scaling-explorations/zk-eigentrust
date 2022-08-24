pub mod ed_on_bn254;
pub mod ops;

use crate::{
	poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254},
	utils::to_wide,
};
use ed_on_bn254::{Point, B8, SUBORDER};
use halo2wrong::{
	curves::{bn256::Fr, FieldExt},
	halo2::arithmetic::Field,
};
use num_bigint::BigUint;
use rand::RngCore;

type Hasher = Poseidon<Fr, 5, Params5x5Bn254>;

fn blh(b: &[u8]) -> Vec<u8> {
	let mut hash = [0; 64];
	blake::hash(512, b, &mut hash).unwrap();
	hash.to_vec()
}

pub struct SecretKey(BigUint, Fr);

impl SecretKey {
	pub fn random<R: RngCore + Clone>(rng: &mut R) -> Self {
		let a = Fr::random(rng.clone());
		let hash: Vec<u8> = blh(&a.to_bytes());
		let sk0 = BigUint::from_bytes_le(&hash[..32]);

		let bytes_wide = to_wide(&hash[32..]);
		let sk1 = Fr::from_bytes_wide(&bytes_wide);
		SecretKey(sk0, sk1)
	}

	pub fn public(&self) -> PublicKey {
		let a = B8.mul_scalar(&self.0.to_bytes_le());
		PublicKey(a.affine())
	}
}

pub struct PublicKey(Point);

#[derive(Clone)]
pub struct Signature {
	big_r: Point,
	s: Fr,
}

pub fn sign(sk: &SecretKey, pk: &PublicKey, m: Fr) -> Signature {
	let inputs = [Fr::zero(), sk.1, m, Fr::zero(), Fr::zero()];
	let r = Hasher::new(inputs).permute()[0];
	let r_bn = BigUint::from_bytes_le(&r.to_bytes());

	// R = B8 * r
	let big_r = B8.mul_scalar(&r.to_bytes()).affine();
	let m_hash_input = [big_r.x, big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let m_hash_bn = BigUint::from_bytes_le(&m_hash.to_bytes());
	// S = r + H(R || A || M) * sk0   (mod n)
	let s = r_bn + &sk.0 * m_hash_bn;
	let s = s % BigUint::from_bytes_le(&SUBORDER.to_bytes());
	let s = Fr::from_bytes_wide(&to_wide(&s.to_bytes_le()));

	Signature { big_r, s }
}

pub fn verify(sig: &Signature, pk: &PublicKey, m: Fr) -> bool {
	// Cl = s * G
	let cl = B8.mul_scalar(&sig.s.to_bytes());
	let m_hash_input = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let pk_h = pk.0.mul_scalar(&m_hash.to_bytes());
	// Cr = R + H(R || A || M) * A
	let cr = sig.big_r.projective().add(&pk_h);
	cr.affine().equals(cl.affine())
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::curves::group::ff::PrimeField;
	use rand::thread_rng;

	#[test]
	fn should_sign_and_verify() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let res = verify(&sig, &pk, m);

		assert!(res);
	}
}
