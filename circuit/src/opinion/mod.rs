/// Native version of Opinion
pub mod native;

use crate::{
	ecc::generic::AssignedPoint,
	integer::AssignedInteger,
	params::{ecc::EccParams, rns::RnsParams},
	Chipset, CommonConfig, FieldExt, HasherChipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter},
	halo2curves::CurveAffine,
	plonk::Error,
};
use std::marker::PhantomData;

const WIDTH: usize = 5;

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
	public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	signature: (
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	),
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
		signature: (
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		),
		public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		OpinionChipset { signature, public_key, _hasher: PhantomData }
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
