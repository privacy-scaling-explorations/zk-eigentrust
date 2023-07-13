/// Native version of Opinion
pub mod native;

use crate::{
	ecdsa::{AssignedPublicKey, AssignedSignature},
	integer::AssignedInteger,
	params::{ecc::EccParams, rns::RnsParams},
	Chipset, CommonConfig, FieldExt, HasherChipset,
};
use halo2::{circuit::Layouter, halo2curves::CurveAffine, plonk::Error};
use std::marker::PhantomData;

const WIDTH: usize = 5;

/// Assigned Attestation variables.
#[derive(Debug, Clone)]
pub struct AssignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Ethereum address of peer being rated
	pub about: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	/// Unique identifier for the action being rated
	pub domain: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	/// Given rating for the action
	pub value: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	/// Optional field for attaching additional information to the attestation
	pub message: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new AssignedAttestation
	pub fn new(
		about: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		domain: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		value: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		message: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { about, domain, value, message }
	}
}

/// Signed Attestation variables.
#[derive(Debug, Clone)]
pub struct SignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Attestation
	attestation: AssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature
	signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new SignedAttestation
	pub fn new(
		attestation: AssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>,
		signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { attestation, signature }
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct OpinionConfig<F: FieldExt, H>
where
	H: HasherChipset<F, WIDTH>,
{
	hasher: H::Config,
}

impl<F: FieldExt, H> OpinionConfig<F, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Construct a new config
	pub fn new(hasher: H::Config) -> Self {
		Self { hasher }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct OpinionChipset<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	H,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
{
	// Attestations
	attestations: Vec<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
	// Public key
	public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	/// Constructs a phantom data for the hasher.
	_hasher: PhantomData<(H, EC)>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, H, P, EC>
	OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, H, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
{
	/// Create a new chip.
	pub fn new(
		attestations: Vec<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
		public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		OpinionChipset { attestations, public_key, _hasher: PhantomData }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, H, P, EC>
	Chipset<N> for OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, H, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
{
	type Config = OpinionConfig<N, H>;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		Ok(())
	}
}
