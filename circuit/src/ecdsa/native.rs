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
		secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine},
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

/// Ecdsa public key
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PublicKey<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>(
	pub(crate) EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>,
)
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>;

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	PublicKey<N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Construct new PublicKey
	pub fn new(p: EcPoint<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
		Self(p)
	}

	/// Convert pk to raw bytes form
	pub fn to_bytes(&self) -> [u8; 64] {
		let x = big_to_fe::<Fp>(self.0.x.value()).to_bytes();
		let y = big_to_fe::<Fp>(self.0.y.value()).to_bytes();
		let mut bytes: [u8; 64] = [0; 64];
		bytes[..32].copy_from_slice(&x);
		bytes[32..].copy_from_slice(&y);
		bytes
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> From<[u8; 64]>
	for PublicKey<N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	fn from(xy: [u8; 64]) -> Self {
		let mut x_bytes: [u8; 32] = [0; 32];
		let mut y_bytes: [u8; 32] = [0; 32];
		x_bytes.copy_from_slice(&xy[..32]);
		y_bytes.copy_from_slice(&xy[32..]);

		let x = Fp::from_bytes(&x_bytes).unwrap();
		let y = Fp::from_bytes(&y_bytes).unwrap();
		let p = EcPoint::new(Integer::from_w(x), Integer::from_w(y));
		Self::new(p)
	}
}

/// Ecdsa signature
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signature<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) r: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) s: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Signature<N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
{
	fn new(
		r: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>, s: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { r, s }
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> From<(Fq, Fq)>
	for Signature<N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
{
	fn from(rs: (Fq, Fq)) -> Self {
		let (r, s) = rs;
		Self::new(Integer::from_w(r), Integer::from_w(s))
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> From<[u8; 64]>
	for Signature<N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
{
	fn from(rs: [u8; 64]) -> Self {
		let mut r_bytes: [u8; 32] = [0; 32];
		let mut s_bytes: [u8; 32] = [0; 32];
		r_bytes.copy_from_slice(&rs[..32]);
		s_bytes.copy_from_slice(&rs[32..]);

		let r = Fq::from_bytes(&r_bytes).unwrap();
		let s = Fq::from_bytes(&s_bytes).unwrap();
		Self::new(Integer::from_w(r), Integer::from_w(s))
	}
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
	pub public_key: PublicKey<N, NUM_LIMBS, NUM_BITS, P, EC>,
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
		let public_key_p = EcPoint::new(public_key_x, public_key_y);
		let public_key = PublicKey::new(public_key_p);
		Self { private_key, public_key }
	}

	/// Generate a signature for a given message.
	/// Note: it does not make sense to do this in wrong field arithmetic
	/// because the signature requires fresh randomness (k) for security reasons so it cannot be
	/// done in a ZK circuit.
	pub fn sign<R: Rng>(&self, msg_hash: Fq, rng: &mut R) -> Signature<N, NUM_LIMBS, NUM_BITS, P> {
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

		Signature::from((r, s))
	}
}

/// Struct for ECDSA verification using wrong field arithmetic.
pub struct EcdsaVerifier<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
where
	P: RnsParams<<Secp256k1Affine as CurveAffine>::Base, N, NUM_LIMBS, NUM_BITS>
		+ RnsParams<<Secp256k1Affine as CurveAffine>::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	signature: Signature<N, NUM_LIMBS, NUM_BITS, P>,
	msg_hash: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
	public_key: PublicKey<N, NUM_LIMBS, NUM_BITS, P, EC>,
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
		signature: Signature<N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: Integer<Fq, N, NUM_LIMBS, NUM_BITS, P>,
		public_key: PublicKey<N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		let s_inv_fq = big_to_fe::<Fq>(signature.s.value()).invert().unwrap();
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
		let Signature { r, .. } = &self.signature;

		let u_1 = self.msg_hash.mul(&self.s_inv).result;
		let u_2 = r.mul(&self.s_inv).result;
		let v_1 = self.g_as_ecpoint.mul_scalar(u_1);
		let v_2 = self.public_key.0.mul_scalar(u_2);
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
		ecdsa::native::{EcdsaKeypair, EcdsaVerifier, PublicKey},
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

		let wrong_pk_point = public_key.0.mul_scalar(Integer::from_w(Fq::from(2u64)));
		let wrong_pk = PublicKey::new(wrong_pk_point);
		let result = EcdsaVerifier::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::new(
			signature,
			Integer::from_w(msg_hash),
			wrong_pk,
		);
		assert!(!result.verify());
	}
}
