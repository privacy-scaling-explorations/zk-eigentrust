pub mod ed_on_bn254;

use crate::poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254};
use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};
use rand::RngCore;

use ed_on_bn254::{Point, B8};

type Hasher = Poseidon<Fr, 5, Params5x5Bn254>;

pub struct SecretKey(Fr, Fr);

impl SecretKey {
	fn random<R: RngCore + Clone>(rng: &mut R) -> Self {
		let seed = [Fr::random(rng); 5];
		let res = Hasher::new(seed).permute();
		SecretKey(res[0], res[1])
	}

	fn public_key(&self) -> PublicKey {
		let a = B8.mul_scalar(&self.0);
		PublicKey(a)
	}
}

pub struct PublicKey(Point);

pub struct Signature {
	big_r: Point,
	s: Fr,
}

pub fn sign(sk: &SecretKey, pk: &PublicKey, m: Fr) -> Signature {
	let input = [Fr::zero(), sk.0, m, Fr::zero(), Fr::zero()];
	// r = H(sk0 || M)
	let r = Hasher::new(input).permute()[0];
	// R = G * r
	let big_r = B8.mul_scalar(&r);
	let m_hash_input = [big_r.x, big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	// s = r + H(R || A || M) * sk0
	let s = r + m_hash * sk.0;

	// (R, s)
	Signature { big_r, s }
}

pub fn verify(sig: &Signature, pk: &PublicKey, m: Fr) -> bool {
	// Cl = s * G
	let cl = B8.mul_scalar(&sig.s);
	let m_hash_input = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let m_hash_8 = m_hash * Fr::from(8);
	// Cr = R + H(R || A || M) * A
	let cr = sig
		.big_r
		.projective()
		.add(&pk.0.mul_scalar(&m_hash_8).projective());
	cr.affine().equals(cl)
}

#[cfg(test)]
mod test {
	use super::*;
	use rand::thread_rng;

	#[test]
	#[ignore = "not passing yet"]
	fn should_sign_and_verify() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public_key();

		let m = Fr::random(&mut rng);

		let sig = sign(&sk, &pk, m);
		let res = verify(&sig, &pk, m);

		assert!(res);
	}
}
