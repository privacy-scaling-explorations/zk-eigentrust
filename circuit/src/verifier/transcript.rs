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
	io::{self, Read, Write},
	marker::PhantomData,
};

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
	fn squeeze_challenge(&mut self) -> LScalar<C, P> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		let mut hasher = self.state.clone();
		let hasher = hasher.squeeze();
		LScalar::new(hasher, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(&mut self, ec_point: &LEcPoint<C, P>) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		// ASK THIS: IS THIS NOT IMPORTANT TO DO LIKE THIS
		let x_scalar = P::compose(ec_point.inner.x.limbs);
		let y_scalar = P::compose(ec_point.inner.y.limbs);

		self.state.update(&[x_scalar]);
		self.state.update(&[y_scalar]);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &LScalar<C, P>) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		self.state.update(&[scalar.inner]);

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
		// No ?
		let _ = self.reader.read_exact(data.as_mut());
		let scalar = C::Scalar::from_repr(data).unwrap();
		let scalar = LScalar::new(scalar, self.loader.clone());
		self.common_scalar(&scalar)?;

		Ok(scalar)
	}

	fn read_ec_point(&mut self) -> Result<LEcPoint<C, P>, VerifierError> {
		let mut compressed = C::Repr::default();
		let _ = self.reader.read_exact(compressed.as_mut());
		let point: C = Option::from(C::from_bytes(&compressed))
			.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof"))
			.unwrap();
		let coordinates = point.coordinates().unwrap();
		let x_coordinate = coordinates.x();
		let y_coordinate = coordinates.y();
		let x = Integer::<
			<C as CurveAffine>::Base,
			<C as CurveAffine>::ScalarExt,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::from_w(x_coordinate.clone());
		let y = Integer::<
			<C as CurveAffine>::Base,
			<C as CurveAffine>::ScalarExt,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::from_w(y_coordinate.clone());

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
	// TODO: Ask return type of this function
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
				io::Error::new(
					io::ErrorKind::Other,
					"cannot write points at infinity to the transcript",
				)
			})
			.unwrap();
		let x = Integer::<
			<C as CurveAffine>::Base,
			<C as CurveAffine>::ScalarExt,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::from_w(coords.x().clone());
		let y = Integer::<
			<C as CurveAffine>::Base,
			<C as CurveAffine>::ScalarExt,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::from_w(coords.y().clone());
		let x_scalar = P::compose(x.limbs);
		let y_scalar = P::compose(y.limbs);

		self.state.update(&[x_scalar]);
		self.state.update(&[y_scalar]);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(&mut self, scalar: &C::ScalarExt) -> Result<(), VerifierError> {
		let default = C::Scalar::default();
		self.state.update(&[default]);
		self.state.update(&[scalar.clone()]);

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
