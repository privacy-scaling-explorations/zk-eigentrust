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
		ff::PrimeField,
		group::Curve,
		secp256k1::{Fq, Secp256k1Affine},
		CurveAffine,
	},
};
use rand::Rng;
use sha3::{Digest, Keccak256};
use std::io::Read;

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
pub struct PublicKey<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
>(pub(crate) EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>)
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt;

/// Implementation just for Secp256k1
impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Construct new PublicKey
	pub fn new(p: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
		Self(p)
	}

	/// Construct an Ethereum address for the given ECDSA public key
	pub fn to_address(&self) -> N {
		let pub_key_bytes = self.to_bytes();

		// Hash with Keccak256
		let mut hasher = Keccak256::new();
		hasher.update(&pub_key_bytes[..]);
		let hashed_public_key = hasher.finalize().to_vec();

		// Get the last 20 bytes of the hash
		let mut address = [0u8; 20];
		address.copy_from_slice(&hashed_public_key[hashed_public_key.len() - 20..]);
		address.reverse();

		let mut address_bytes = <N as PrimeField>::Repr::default();
		address.as_ref().read(address_bytes.as_mut()).unwrap();

		N::from_repr(address_bytes).unwrap()
	}
}

/// Implementation just for Secp256k1
impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Convert pk to raw bytes form
	pub fn to_bytes(&self) -> Vec<u8> {
		let x = big_to_fe::<C::Base>(self.0.x.value()).to_repr();
		let y = big_to_fe::<C::Base>(self.0.y.value()).to_repr();
		let mut bytes = Vec::new();
		bytes.extend(x.as_ref());
		bytes.extend(y.as_ref());
		bytes
	}

	/// Convert bytes into pk
	pub fn from_bytes(xy: Vec<u8>) -> Self {
		let mut xy_mut: &[u8] = xy.as_ref();
		let mut x_repr = <C::Base as PrimeField>::Repr::default();
		let mut y_repr = <C::Base as PrimeField>::Repr::default();
		xy_mut.read_exact(x_repr.as_mut()).unwrap();
		xy_mut.read_exact(y_repr.as_mut()).unwrap();
		let x = <C::Base as PrimeField>::from_repr(x_repr).unwrap();
		let y = <C::Base as PrimeField>::from_repr(y_repr).unwrap();
		let p = EcPoint::new(Integer::from_w(x), Integer::from_w(y));
		Self::new(p)
	}
}

/// Ecdsa signature
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signature<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	pub(crate) r: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) s: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Signature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	fn new(
		r: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { r, s }
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> From<[u8; 64]>
	for Signature<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<Fq, N, NUM_LIMBS, NUM_BITS>,
{
	fn from(rs: [u8; 64]) -> Self {
		let mut r_bytes: [u8; 32] = [0; 32];
		let mut s_bytes: [u8; 32] = [0; 32];
		r_bytes.copy_from_slice(&rs[..32]);
		s_bytes.copy_from_slice(&rs[32..]);

		Self::from((r_bytes, s_bytes))
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> From<([u8; 32], [u8; 32])>
	for Signature<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<Fq, N, NUM_LIMBS, NUM_BITS>,
{
	fn from(rs: ([u8; 32], [u8; 32])) -> Self {
		let (r_bytes, s_bytes) = rs;

		let r = Fq::from_bytes(&r_bytes).unwrap();
		let s = Fq::from_bytes(&s_bytes).unwrap();
		Self::new(Integer::from_w(r), Integer::from_w(s))
	}
}

/// Keypair struct for ECDSA signature
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EcdsaKeypair<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Private key is a random integer in the range from Fq
	pub private_key: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	/// Public key is a point on the Secp256k1 curve
	pub public_key: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaKeypair<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Generate a random keypair
	pub fn generate_keypair<R: Rng>(rng: &mut R) -> Self {
		let private_key_fq = C::ScalarExt::random(rng);
		Self::from_private_key(private_key_fq)
	}

	/// Generate a keypair from a given private key
	pub fn from_private_key(private_key_fq: C::ScalarExt) -> Self {
		let private_key = Integer::from_w(private_key_fq);
		let public_key_affine = (C::generator() * private_key_fq).to_affine();

		let c = public_key_affine.coordinates().unwrap();
		let public_key_x = Integer::from_w(*c.x());
		let public_key_y = Integer::from_w(*c.y());
		let public_key_p = EcPoint::new(public_key_x, public_key_y);
		let public_key = PublicKey::new(public_key_p);
		Self { private_key, public_key }
	}

	/// Generate a signature for a given message.
	/// Note: it does not make sense to do this in wrong field arithmetic
	/// because the signature requires fresh randomness (k) for security reasons so it cannot be
	/// done in a ZK circuit.
	pub fn sign<R: Rng>(
		&self, msg_hash: C::ScalarExt, rng: &mut R,
	) -> Signature<C, N, NUM_LIMBS, NUM_BITS, P> {
		// Draw randomness
		let k = C::ScalarExt::random(rng);
		let k_inv = k.invert().unwrap();

		// Calculate `r`
		let r_point = (C::generator() * k).to_affine().coordinates().unwrap();
		let x = r_point.x();
		let r = mod_n::<C>(*x);
		let private_key_fq = big_to_fe::<C::ScalarExt>(self.private_key.value());
		// Calculate `s`
		let s = k_inv * (msg_hash + (r * private_key_fq));

		Signature::new(Integer::from_w(r), Integer::from_w(s))
	}
}

/// Struct for ECDSA verification using wrong field arithmetic.
pub struct EcdsaVerifier<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	signature: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
	msg_hash: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	public_key: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	s_inv: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	g_as_ecpoint: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaVerifier<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Construct the verifier given the signature, message hash and a public key
	pub fn new(
		signature: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		public_key: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		let s_inv_fq = big_to_fe::<C::ScalarExt>(signature.s.value()).invert().unwrap();
		let s_inv = Integer::from_w(s_inv_fq);

		let g = C::generator().coordinates().unwrap();
		let g_as_ecpoint = EcPoint::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(*g.x()),
			Integer::from_w(*g.y()),
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
	use halo2::halo2curves::{
		bn256::Fr,
		ff::PrimeField,
		secp256k1::{Fq, Secp256k1Affine},
	};

	#[test]
	fn should_verify_ecdsa_signature() {
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = Fq::from_u128(123456789);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();
		let verifier =
			EcdsaVerifier::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::new(
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
			EcdsaKeypair::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = Fq::from_u128(123456789);
		let signature = keypair.sign(msg_hash.clone(), rng);
		let public_key = keypair.public_key.clone();

		let wrong_pk_point = public_key.0.mul_scalar(Integer::from_w(Fq::from(2u64)));
		let wrong_pk = PublicKey::new(wrong_pk_point);
		let result =
			EcdsaVerifier::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::new(
				signature,
				Integer::from_w(msg_hash),
				wrong_pk,
			);
		assert!(!result.verify());
	}
}
