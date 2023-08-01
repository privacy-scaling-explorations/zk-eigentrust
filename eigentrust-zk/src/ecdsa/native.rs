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
		secp256k1::{Fp, Fq, Secp256k1Affine},
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

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, PartialOrd, Ord)]
/// Recovery id struct
pub struct RecoveryId(u8);

impl RecoveryId {
	/// Create a new [`RecoveryId`] from the following 1-bit argument:
	///
	/// - `is_y_odd`: is the affine y-coordinate of 𝑘×𝑮 odd?
	pub const fn new(is_y_odd: bool) -> Self {
		Self(is_y_odd as u8)
	}

	/// Is the affine y-coordinate of 𝑘×𝑮 odd?
	pub const fn is_y_odd(self) -> bool {
		(self.0 & 1) != 0
	}

	/// Convert a `u8` into a [`RecoveryId`].
	pub const fn from_byte(byte: u8) -> Self {
		Self(byte)
	}

	/// Convert this [`RecoveryId`] into a `u8`.
	pub const fn to_byte(self) -> u8 {
		self.0
	}
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
		let mut address = [0u8; 32];
		address[12..].copy_from_slice(&hashed_public_key[hashed_public_key.len() - 20..]);
		address.reverse();

		let mut address_bytes = <N as PrimeField>::Repr::default();
		address.as_ref().read_exact(address_bytes.as_mut()).unwrap();

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

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> From<C>
	for PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	fn from(c_affine: C) -> Self {
		let c = c_affine.coordinates().unwrap();
		let public_key_x = Integer::from_w(*c.x());
		let public_key_y = Integer::from_w(*c.y());
		let public_key_p = EcPoint::new(public_key_x, public_key_y);
		Self::new(public_key_p)
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
	pub(crate) rec_id: RecoveryId,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Signature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	fn new(
		r: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>, rec_id: RecoveryId,
	) -> Self {
		Self { r, s, rec_id }
	}
}

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Signature<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<Fq, N, NUM_LIMBS, NUM_BITS>,
{
	/// Construct from raw bytes
	pub fn from_bytes(bytes: Vec<u8>) -> Self {
		let mut r_bytes: [u8; 32] = [0; 32];
		let mut s_bytes: [u8; 32] = [0; 32];
		r_bytes.copy_from_slice(&bytes[..32]);
		s_bytes.copy_from_slice(&bytes[32..]);

		let r = Fq::from_bytes(&r_bytes).unwrap();
		let s = Fq::from_bytes(&s_bytes).unwrap();

		let rec_id = RecoveryId::from_byte(bytes[65]);

		Self::new(Integer::from_w(r), Integer::from_w(s), rec_id)
	}

	/// Convert to raw bytes
	pub fn to_bytes(&self) -> Vec<u8> {
		let r_bytes = self.r.value().to_bytes_le();
		let s_bytes = self.s.value().to_bytes_le();

		let mut bytes = Vec::new();
		bytes.extend(&r_bytes);
		bytes.extend(&s_bytes);
		bytes
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
		let public_key = PublicKey::from(public_key_affine);
		Self { private_key, public_key }
	}

	/// Generate a signature for a given message.
	/// Note: it does not make sense to do this in wrong field arithmetic
	/// because the signature requires fresh randomness (k) for security reasons so it cannot be
	/// done in a ZK circuit.
	pub fn sign_inner<R: Rng>(
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

		let y_is_odd = bool::from(r_point.y().is_odd());
		let rec_id = RecoveryId::new(y_is_odd);

		Signature::new(Integer::from_w(r), Integer::from_w(s), rec_id)
	}

	/// Recover public key, given the signature and message hash
	pub fn recover_public_key(
		&self, sig: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC> {
		let Signature { r, s, rec_id } = sig.clone();
		let msg_hash_fe = big_to_fe::<C::ScalarExt>(msg_hash.value());
		let r_fe = big_to_fe::<C::ScalarExt>(r.value());
		let s_fe = big_to_fe::<C::ScalarExt>(s.value());
		let y_odd = rec_id.to_byte();

		let mut big_r_bytes = Vec::new();
		big_r_bytes.extend(r_fe.to_repr().as_ref());
		big_r_bytes.push(y_odd);

		let mut big_r_repr = C::Repr::default();
		big_r_repr.as_mut().copy_from_slice(&big_r_bytes);
		let big_r = C::from_bytes(&big_r_repr).unwrap();

		let r_inv = r_fe.invert().unwrap();
		let u1 = -(r_inv * msg_hash_fe);
		let u2 = r_inv * s_fe;
		let pk = C::generator() * u1 + big_r * u2;

		let pk_p = PublicKey::from(pk.to_affine());

		// Verification - Sanity check
		{
			let verifier =
				EcdsaVerifier::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(sig, msg_hash, pk_p.clone());

			assert!(verifier.verify());
		}

		pk_p
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

impl<N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaKeypair<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<Fp, N, NUM_LIMBS, NUM_BITS> + RnsParams<Fq, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<Secp256k1Affine>,
{
	/// Signing algorithm just for secp256k1
	pub fn sign<R: Rng>(
		&self, msg_hash: Fq, rng: &mut R,
	) -> Signature<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P> {
		let sig = self.sign_inner(msg_hash, rng);
		let Signature { r, s, rec_id } = sig;
		let s_fe = big_to_fe::<Fq>(s.value());

		// Find n / 2 for scalar field
		let border = (Fq::zero() - Fq::one()) * Fq::from(2).invert().unwrap();
		let is_high = s_fe >= border;
		let is_y_odd = rec_id.is_y_odd() ^ is_high;
		let new_rec_id = RecoveryId::new(is_y_odd);

		// Normalise s, if is_high, rotate it below the n / 2
		let s_low = if is_high { -s_fe } else { s_fe };
		let new_s = Integer::from_w(s_low);

		let new_sig = Signature::new(r, new_s, new_rec_id);

		new_sig
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

	#[test]
	fn should_recover_public_key() {
		let rng = &mut rand::thread_rng();
		let keypair =
		EcdsaKeypair::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let msg_hash = Fq::from_u128(123456789);
		let sig = keypair.sign(msg_hash.clone(), rng);

		let public_key = keypair.public_key.clone();
		let recovered_public_key = keypair.recover_public_key(sig, Integer::from_w(msg_hash));
		assert_eq!(public_key, recovered_public_key);
	}
}
