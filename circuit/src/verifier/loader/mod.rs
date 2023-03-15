use crate::{ecc::EccAddConfig, integer::rns::RnsParams, CommonConfig};
use halo2::{circuit::Layouter, halo2curves::CurveAffine};
use native::{NUM_BITS, NUM_LIMBS};
use std::{marker::PhantomData, rc::Rc};

/// Native version of the loader
pub mod native;

// TODO: FOR Halo2LScalar: Use AssignedCell for inner value
// TODO: For Halo2LEcPoint: Use AssignedPoint for inner value

struct Halo2Loader<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	layouter: Rc<L>,
	config: CommonConfig,
	ecc_add: EccAddConfig,
	// TODO: Add configs for the rest of the operations: mul_scalar
	_curve: PhantomData<C>,
	_p: PhantomData<P>,
}
