pub mod ed_on_bn254;
pub mod reduce;

use crate::poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254};
use halo2curves::FieldExt;
use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};
use rand::RngCore;
use ed_on_bn254::{Point, B8};
use blake::Blake;

type Hasher = Poseidon<Fr, 5, Params5x5Bn254>;

pub struct SecretKey(Fr, Fr);

impl SecretKey {
	fn random<R: RngCore + Clone>(rng: &mut R) -> Self {
		let mut blh = Blake::new(512).unwrap();
		blh.update(&Fr::random(rng).to_bytes());

		let mut result: [u8; 64] = [0; 64];
		blh.finalise(&mut result);

		let mut part1: [u8; 64] = [0; 64];
		let mut part2: [u8; 64] = [0; 64];
		part1[..32].copy_from_slice(&result[..32]);
		part2[..32].copy_from_slice(&result[32..64]);

		let sk0 = Fr::from_bytes_wide(&part1);
		let sk1 = Fr::from_bytes_wide(&part2);
		SecretKey(sk0, sk1)
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

pub fn sign_schnorr<R: RngCore>(sk: &SecretKey, pk: &PublicKey, m: Fr, rng: &mut R) -> Signature {
	// random k
	let k = Fr::random(rng);

	let r = B8.mul_scalar(&k);
	let m_hash_input = [r.x, r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let s = k + sk.0 * m_hash;
	
	Signature { big_r: r, s }
}

pub fn sign(sk: &SecretKey, pk: &PublicKey, m: Fr) -> Signature {
	let input = [Fr::zero(), sk.1, m, Fr::zero(), Fr::zero()];
	// r = H(sk1 || M)
	let r = Hasher::new(input).permute()[0];
	// R = G * r
	let big_r = B8.mul_scalar(&r);
	let m_hash_input = [big_r.x, big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	// s = r + H(R || A || M) * sk0   (mod n)
	let s = r + m_hash * sk.0;

	// (R, s)
	Signature { big_r, s }
}

pub fn verify(sig: &Signature, pk: &PublicKey, m: Fr) -> bool {
	// Cl = s * G
	let cl = B8.mul_scalar(&sig.s);
	let m_hash_input = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let pk_h = pk.0.mul_scalar(&m_hash);
	// Cr = R + H(R || A || M) * A
	let cr = sig.big_r.projective().add(&pk_h.projective());
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

	#[test]
	// #[ignore = "not passing yet"]
	fn should_sign_and_verify_schnorr() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public_key();

		let m = Fr::random(&mut rng);

		let sig = sign_schnorr(&sk, &pk, m, &mut rng);
		let res = verify(&sig, &pk, m);

		assert!(res);
	}
}
