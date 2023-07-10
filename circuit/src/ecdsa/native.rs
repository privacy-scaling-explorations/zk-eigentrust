use crate::{
	ecc::generic::native::EcPoint,
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	utils::{big_to_fe, fe_to_big},
	FieldExt,
};
use halo2::{
	arithmetic::Field,
	halo2curves::{
		group::Curve,
		secp256k1::{Fq, Secp256k1, Secp256k1Affine},
		CurveAffine,
	},
};
use rand::Rng;

/// Helper function to convert Fp element to Fq element
fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar
where
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	let x_big = fe_to_big(x);
	big_to_fe(x_big)
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
		let public_key_affine = (Secp256k1::generator() * private_key_fq).to_affine();
		let public_key_x = Integer::from_w(public_key_affine.x);
		let public_key_y = Integer::from_w(public_key_affine.y);
		let public_key = EcPoint::new(public_key_x, public_key_y);
		Self { private_key, public_key }
	}

	/// Generate a signature for a given message.
	/// Note: it does not make sense to do this in wrong field arithmetic
	/// because the signature requires fresh randomness (k) for security reasons so it cannot be
	/// done in a ZK circuit.
	pub fn sign<R: Rng>(
		&self, msg_hash: Fq, rng: &mut R,
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
		let r = mod_n::<Secp256k1Affine>(*x);
		let private_key_fq: Fq = big_to_fe(self.private_key.value());
		// Calculate `s`
		let s = k_inv * (msg_hash + (r * private_key_fq));

		(Integer::from_w(r), Integer::from_w(s))
	}
}

/// Struct for ECDSA verification using wrong field arithmetic.
pub struct EcdsaVerifier<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	signature: (
		Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	),
	msg_hash: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	public_key: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
	s_inv: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	g_as_ecpoint: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaVerifier<N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Construct the verifier given the signature, message hash and a public key
	pub fn new(
		signature: (
			Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
			Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		),
		msg_hash: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		public_key: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		let s_inv_fq = big_to_fe::<Fq>(signature.1.value()).invert().unwrap();
		let s_inv = Integer::from_w(s_inv_fq);

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);

		Self { signature, msg_hash, public_key, s_inv, g_as_ecpoint }
	}
	/// Verify a signature for a given message hash and public key using wrong field arithmetic
	/// Similar to the ZK circuit setting instead of computing s_inverse we take it in as an advice value
	pub fn verify(&self) -> bool {
		let (r, _) = &self.signature;

		let u_1 = self.msg_hash.mul(&self.s_inv).result;
		let u_2 = r.mul(&self.s_inv).result;
		let v_1 = self.g_as_ecpoint.mul_scalar(u_1);
		let v_2 = self.public_key.mul_scalar(u_2);
		let r_point = v_1.add(&v_2);

		let x_candidate = r_point.x;
		for i in 0..NUM_LIMBS {
			if x_candidate.limbs[i] != r.limbs[i] {
				return false;
			}
		}
		true
	}
}

#[cfg(test)]
mod test {
	use crate::{
		ecdsa::native::{EcdsaKeypair, EcdsaVerifier},
		integer::native::Integer,
		params::ecc::secp256k1::Secp256k1Params,
		params::rns::secp256k1::Secp256k1_4_68,
	};
	use halo2::halo2curves::{bn256::Fr, ff::PrimeField, secp256k1::Fq};

	#[test]
	fn should_verify_ecdsa_signature() {
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = Fq::from_u128(123456789);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();
		let verifier = EcdsaVerifier::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::new(
			signature,
			Integer::from_w(msg_hash),
			public_key,
		);
		assert!(verifier.verify());
	}

	#[test]
	fn should_not_verify_invalid_ecdsa_signature() {
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = Fq::from_u128(123456789);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();
		let result = EcdsaVerifier::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::new(
			signature,
			Integer::from_w(msg_hash),
			public_key.mul_scalar(Integer::from_w(Fq::from(2u64))),
		);
		assert!(!result.verify());
	}
}
