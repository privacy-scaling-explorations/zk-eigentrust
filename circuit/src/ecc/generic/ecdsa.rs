use crate::{
	ecc::generic::native::EcPoint,
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	utils::big_to_fe,
	FieldExt,
};

use halo2::{
	arithmetic::Field,
	halo2curves::{
		ff::{FromUniformBytes, PrimeField},
		group::Curve,
		secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine},
		CurveAffine,
	},
};
use num_bigint::BigUint;
use rand::Rng;

/// Helper function to convert Fp element to Fq element
pub fn fp_to_fq(x: Fp) -> Fq {
	let mut x_repr = [0u8; 32];
	x_repr.copy_from_slice(x.to_repr().as_ref());
	let mut x_bytes = [0u8; 64];
	x_bytes[..32].copy_from_slice(&x_repr[..]);
	Fq::from_uniform_bytes(&x_bytes)
}

/// Keypair struct for ECDSA signature
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EcdsaKeypair<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Private key is a random integer in the range from Fq
	pub private_key: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	/// Public key is a point on the Secp256k1 curve
	pub public_key: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaKeypair<N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Generate a random keypair
	pub fn generate_keypair<R: Rng>(rng: &mut R) -> Self {
		let private_key_fq = Fq::random(rng);
		Self::from_private_key(private_key_fq)
	}

	/// Generate a keypair from a given private key
	pub fn from_private_key(private_key_fq: Fq) -> Self {
		let private_key = Integer::from_w(private_key_fq);
		let public_key_affine = (Secp256k1::generator() * &private_key_fq).to_affine();
		let public_key_x = Integer::from_w(public_key_affine.x.clone());
		let public_key_y = Integer::from_w(public_key_affine.y.clone());
		let public_key = EcPoint::new(public_key_x, public_key_y);
		Self { private_key, public_key }
	}

	/// Generate a signature for a given message.
	/// Note: it does not make sense to do this in wrong field arithmetic
	/// because the signature requires fresh randomness (k) for security reasons so it cannot be
	/// done in a ZK circuit.
	pub fn sign<R: Rng>(
		&self, msg_hash: BigUint, rng: &mut R,
	) -> (
		Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	) {
		// Draw randomness
		let k = Fq::random(rng);
		let k_inv = k.invert().unwrap();

		// Calculate `r`
		let r_point = (Secp256k1::generator() * k).to_affine().coordinates().unwrap();
		let x = r_point.x();
		let r = fp_to_fq(*x);
		let msg_hash_fq: Fq = big_to_fe(msg_hash);
		let private_key_fq: Fq = big_to_fe(self.private_key.value());
		// Calculate `s`
		let s = k_inv * (msg_hash_fq + (r * private_key_fq));

		(Integer::from_w(r), Integer::from_w(s))
	}
}

/// Struct for ECDSA verification using wrong field arithmetic.
pub struct EcdsaVerify<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	phantom: std::marker::PhantomData<(N, P, EC)>,
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaVerify<N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Verify a signature for a given message hash and public key using wrong field arithmetic
	/// Similar to the ZK circuit setting instead of computing s_inverse we take it in as an advice value
	pub fn verify_signature_no_pubkey_check(
		signature: (
			Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
			Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		),
		msg_hash: BigUint, public_key: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> bool {
		let (r, s) = signature;
		let msg_hash_integer = Integer::<Fq, N, NUM_LIMBS, NUM_BITS, P>::new(msg_hash);
		let s_inv = s.invert();
		let u_1 = msg_hash_integer.mul(&s_inv).result;
		let u_2 = r.mul(&s_inv).result;

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);

		let v_1 = g_as_ecpoint.mul_scalar(u_1);
		let v_2 = public_key.mul_scalar(u_2);

		let r_point = v_1.add(&v_2);
		let x_candidate = r_point.x;
		for i in 0..NUM_LIMBS {
			if x_candidate.limbs[i] != r.limbs[i] {
				return false;
			}
		}
		return true;
	}
}

#[cfg(test)]
mod test {
	use crate::{
		ecc::generic::ecdsa::{EcdsaKeypair, EcdsaVerify},
		integer::native::Integer,
		params::ecc::secp256k1::Secp256k1Params,
		params::rns::secp256k1::Secp256k1_4_68,
		utils::big_to_fe,
	};
	use halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::Fr,
			ff::PrimeField,
			secp256k1::{Fq, Secp256k1, Secp256k1Affine},
		},
	};
	use num_bigint::BigUint;
	#[test]
	fn should_verify_ecdsa_signature() {
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = BigUint::from(123456789u64);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();
		let result = EcdsaVerify::<Fr, 4, 68,  Secp256k1_4_68, Secp256k1Params>::verify_signature_no_pubkey_check(
            signature,
            msg_hash,
            public_key,
        );
		assert!(result);
	}

	#[test]
	fn should_not_verify_invalid_ecdsa_signature() {
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = BigUint::from(123456789u64);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();
		let result = EcdsaVerify::<Fr, 4, 68,  Secp256k1_4_68, Secp256k1Params>::verify_signature_no_pubkey_check(
            signature,
            msg_hash,
            public_key.mul_scalar(Integer::from_w(Fq::from(2u64))),
        );
		assert!(!result);
	}
}
