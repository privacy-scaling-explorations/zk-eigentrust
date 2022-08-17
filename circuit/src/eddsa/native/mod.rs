pub mod ed_on_bn254;

use std::str::FromStr;

use crate::poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254};
use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};
use rand::RngCore;
use num_bigint::BigUint;
use ed_on_bn254::{Point, B8};

type Hasher = Poseidon<Fr, 5, Params5x5Bn254>;

fn blh(b: &[u8]) -> Vec<u8> {
    let mut hash = [0; 64];
    blake::hash(512, b, &mut hash).unwrap();
    hash.to_vec()
}

pub struct SecretKey(BigUint);

impl SecretKey {
	fn random<R: RngCore + Clone>(rng: &mut R) -> Self {
		let a = Fr::random(rng.clone());
		let hash: Vec<u8> = blh(&a.to_bytes());
		let h: Vec<u8> = hash[..32].to_vec();
		let sk = BigUint::from_bytes_le(&h[..]);
		SecretKey(sk >> 3)
	}

	fn public_key(&self) -> PublicKey {
		let a = B8.mul_scalar(&self.0.to_bytes_le());
		PublicKey(a)
	}
}

pub struct PublicKey(Point);

pub struct Signature {
	big_r: Point,
	s: BigUint,
}

pub fn sign<R: RngCore>(sk: &SecretKey, pk: &PublicKey, m: Fr, rng: &mut R) -> Signature {
	// random k
	let k = BigUint::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();

	let r = B8.mul_scalar(&k.to_bytes_le());
	let m_hash_input = [r.x, r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let m_hash_bn = BigUint::from_bytes_le(&m_hash.to_bytes());
	let s = k + &sk.0 * m_hash_bn;
	let s = s % BigUint::from_str("2736030358979909402780800718157159386076813972158567259200215660948447373041").unwrap();
	
	Signature { big_r: r, s }
}

pub fn verify(sig: &Signature, pk: &PublicKey, m: Fr) -> bool {
	// Cl = s * G
	let cl = B8.mul_scalar(&sig.s.to_bytes_le());
	let m_hash_input = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, m];
	let m_hash = Hasher::new(m_hash_input).permute()[0];
	let pk_h = pk.0.mul_scalar(&m_hash.to_bytes());
	// Cr = R + H(R || A || M) * A
	let cr = sig.big_r.projective().add(&pk_h.projective());
	cr.affine().equals(cl)
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2curves::group::ff::PrimeField;
	use rand::thread_rng;

	#[test]
	fn should_sign_and_verify() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public_key();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m, &mut rng);
		let res = verify(&sig, &pk, m);

		assert!(res);
	}
}
