use super::loader::{LEcPoint, LScalar, NativeLoader, NUM_BITS, NUM_LIMBS};
use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
	params::RoundParams,
	poseidon::native::sponge::PoseidonSponge,
};
use halo2::halo2curves::{Coordinates, CurveAffine};
use snark_verifier::{
	loader::native::NativeLoader as NativeSVLoader,
	util::{
		arithmetic::PrimeField,
		transcript::{Transcript, TranscriptRead, TranscriptWrite},
	},
	Error as VerifierError,
};
use std::{
	io::{ErrorKind, Read, Write},
	marker::PhantomData,
};

// TODO: Implement PoseidonRead with NativeSVLoader from snark-verifier

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

impl<RD: Read, C: CurveAffine, P, R> PoseidonRead<RD, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Create new PoseidonRead transcript
	pub fn new(reader: RD, loader: NativeLoader<C, P>) -> Self {
		Self { reader, state: PoseidonSponge::new(), loader }
	}
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
	fn squeeze_challenge(&mut self) -> LScalar<C, P> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		let mut hasher = self.state.clone();
		let val = hasher.squeeze();
		LScalar::new(val, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(&mut self, ec_point: &LEcPoint<C, P>) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default]);

		self.state.update(&ec_point.inner.x.limbs);
		self.state.update(&ec_point.inner.y.limbs);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &LScalar<C, P>) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default, scalar.inner]);

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
		let mut data = <C::Scalar as PrimeField>::Repr::default();
		self.reader.read_exact(data.as_mut()).map_err(|err| {
			VerifierError::Transcript(
				err.kind(),
				"invalid field element encoding in proof".to_string(),
			)
		})?;
		let scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
			VerifierError::Transcript(
				ErrorKind::Other,
				"invalid field element encoding in proof".to_string(),
			)
		})?;
		let scalar = LScalar::new(scalar, self.loader.clone());
		self.common_scalar(&scalar)?;

		Ok(scalar)
	}

	fn read_ec_point(&mut self) -> Result<LEcPoint<C, P>, VerifierError> {
		let mut compressed = C::Repr::default();
		self.reader.read_exact(compressed.as_mut()).map_err(|err| {
			VerifierError::Transcript(
				err.kind(),
				"invalid field element encoding in proof".to_string(),
			)
		})?;
		let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
			VerifierError::Transcript(
				ErrorKind::Other,
				"invalid point encoding in proof".to_string(),
			)
		})?;
		let coordinates = point.coordinates().unwrap();
		let x_coordinate = coordinates.x();
		let y_coordinate = coordinates.y();
		let x = Integer::from_w(x_coordinate.clone());
		let y = Integer::from_w(y_coordinate.clone());

		let ec_point = EcPoint::new(x, y);
		let point = LEcPoint { inner: ec_point, loader: self.loader.clone() };
		self.common_ec_point(&point)?;

		Ok(point)
	}
}

/// PoseidonWrite
pub struct PoseidonWrite<W: Write, C: CurveAffine, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	writer: W,
	state: PoseidonSponge<C::Scalar, WIDTH, R>,
	loader: NativeSVLoader,
	_p: PhantomData<P>,
}

impl<W: Write, C: CurveAffine, P, R> PoseidonWrite<W, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Create a new poseidon transcript writer
	pub fn new(writer: W) -> Self {
		Self { writer, state: PoseidonSponge::new(), loader: NativeSVLoader, _p: PhantomData }
	}
}

impl<W: Write, C: CurveAffine, P, R> Transcript<C, NativeSVLoader> for PoseidonWrite<W, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Returns [`Loader`].
	fn loader(&self) -> &NativeSVLoader {
		&self.loader
	}

	/// Squeeze a challenge.
	fn squeeze_challenge(&mut self) -> C::ScalarExt {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		let mut hasher = self.state.clone();
		hasher.squeeze()
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(&mut self, ec_point: &C) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		let coords: Coordinates<C> = Option::from(ec_point.coordinates())
			.ok_or_else(|| {
				VerifierError::Transcript(
					ErrorKind::Other,
					"cannot write points at infinity to the transcript".to_string(),
				)
			})
			.unwrap();

		let x: Integer<_, _, NUM_LIMBS, NUM_BITS, P> = Integer::from_w(coords.x().clone());
		let y: Integer<_, _, NUM_LIMBS, NUM_BITS, P> = Integer::from_w(coords.y().clone());

		self.state.update(&x.limbs);
		self.state.update(&y.limbs);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &C::ScalarExt) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default, scalar.clone()]);

		Ok(())
	}
}

impl<W: Write, C: CurveAffine, P, R> TranscriptWrite<C> for PoseidonWrite<W, C, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,

	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Write a scalar.
	fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), VerifierError> {
		self.common_scalar(&scalar)?;
		let data = scalar.to_repr();
		self.writer.write_all(data.as_ref()).unwrap();

		Ok(())
	}

	/// Write a elliptic curve point.
	fn write_ec_point(&mut self, ec_point: C) -> Result<(), VerifierError> {
		self.common_ec_point(&ec_point)?;
		let compressed = ec_point.to_bytes();
		self.writer.write_all(compressed.as_ref()).unwrap();

		Ok(())
	}
}
