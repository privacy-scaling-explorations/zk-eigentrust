use super::loader::{LEcPoint, LScalar, NativeLoader, NUM_BITS, NUM_LIMBS};
use crate::{
	integer::rns::RnsParams, params::RoundParams, poseidon::native::sponge::PoseidonSponge,
};
use halo2::halo2curves::CurveAffine;
use snark_verifier::{
	loader::native::NativeLoader as NativeSVLoader,
	util::transcript::{Transcript, TranscriptRead, TranscriptWrite},
	Error as VerifierError,
};
use std::io::{Read, Write};

const WIDTH: usize = 5;

/// PoseidonRead
pub struct PoseidonRead<RD: Read, C: CurveAffine, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	reader: RD,
	state: PoseidonSponge<C::Scalar, WIDTH, R>,
	loader: NativeLoader<C, P>,
}

impl<RD: Read, C: CurveAffine, P, R> Transcript<C, NativeLoader<C, P>> for PoseidonRead<RD, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Returns [`Loader`].
	fn loader(&self) -> &NativeLoader<C, P> {
		&self.loader
	}

	/// Squeeze a challenge.
	// TODO: CHECK THE CORRECTNESS
	fn squeeze_challenge(&mut self) -> LScalar<C, P> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		let hasher = self.state.squeeze();
		LScalar::new(hasher, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(&mut self, ec_point: &LEcPoint<C, P>) -> Result<(), VerifierError> {
		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &LScalar<C, P>) -> Result<(), VerifierError> {
		Ok(())
	}
}

impl<RD: Read, C: CurveAffine, P, R> TranscriptRead<C, NativeLoader<C, P>>
	for PoseidonRead<RD, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	fn read_scalar(&mut self) -> Result<LScalar<C, P>, VerifierError> {
		Err(VerifierError::InvalidInstances)
	}

	fn read_ec_point(&mut self) -> Result<LEcPoint<C, P>, VerifierError> {
		Err(VerifierError::InvalidInstances)
	}
}

/// PoseidonWrite
pub struct PoseidonWrite<W: Write, C: CurveAffine, R>
where
	R: RoundParams<C::Scalar, WIDTH>,
{
	writer: W,
	state: PoseidonSponge<C::Scalar, WIDTH, R>,
	loader: NativeSVLoader,
}

impl<W: Write, C: CurveAffine, R> Transcript<C, NativeSVLoader> for PoseidonWrite<W, C, R>
where
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Returns [`Loader`].
	fn loader(&self) -> &NativeSVLoader {
		&self.loader
	}

	/// Squeeze a challenge.
	fn squeeze_challenge(&mut self) -> C::ScalarExt {
		C::ScalarExt::default()
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(&mut self, ec_point: &C) -> Result<(), VerifierError> {
		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &C::ScalarExt) -> Result<(), VerifierError> {
		Ok(())
	}
}

impl<W: Write, C: CurveAffine, R> TranscriptWrite<C> for PoseidonWrite<W, C, R>
where
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Write a scalar.
	fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), VerifierError> {
		Ok(())
	}

	/// Write a elliptic curve point.
	fn write_ec_point(&mut self, ec_point: C) -> Result<(), VerifierError> {
		Ok(())
	}
}
