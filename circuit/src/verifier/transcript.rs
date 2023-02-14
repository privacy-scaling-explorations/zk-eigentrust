use crate::{params::RoundParams, poseidon::native::sponge::PoseidonSponge, utils::to_wide};
use halo2::{
	arithmetic::FieldExt,
	halo2curves::{group::ff::PrimeField, Coordinates, CurveAffine},
	transcript::{
		Challenge255, EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer,
		TranscriptWrite, TranscriptWriterBuffer,
	},
};
use std::io::{self, Read, Write};

const WIDTH: usize = 5;

/// PoseidonRead
pub struct PoseidonRead<R: Read, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> {
	reader: R,
	state: PoseidonSponge<C::Scalar, WIDTH, P>,
}

impl<R: Read, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> TranscriptRead<C, Challenge255<C>>
	for PoseidonRead<R, C, P>
{
	fn read_point(&mut self) -> io::Result<C> {
		let mut compressed = C::Repr::default();
		self.reader.read_exact(compressed.as_mut())?;

		let point: C = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
			io::Error::new(io::ErrorKind::Other, "invalid point encoding in proof")
		})?;
		self.common_point(point)?;

		Ok(point)
	}

	fn read_scalar(&mut self) -> io::Result<C::Scalar> {
		let mut data = <C::Scalar as PrimeField>::Repr::default();
		self.reader.read_exact(data.as_mut())?;

		let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data)).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::Other,
				"invalid field element encoding in proof",
			)
		})?;
		self.common_scalar(scalar)?;

		Ok(scalar)
	}
}

impl<R: Read, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> Transcript<C, Challenge255<C>>
	for PoseidonRead<R, C, P>
{
	fn squeeze_challenge(&mut self) -> Challenge255<C> {
		let res = self.state.squeeze();
		let result = to_wide(res.to_repr().as_ref());
		Challenge255::<C>::new(&result)
	}

	fn common_point(&mut self, point: C) -> io::Result<()> {
		let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::Other,
				"cannot write points at infinity to the transcript",
			)
		})?;
		let x = to_wide(coords.x().to_repr().as_ref());
		let y = to_wide(coords.y().to_repr().as_ref());
		let x_f = C::ScalarExt::from_bytes_wide(&x);
		let y_f = C::ScalarExt::from_bytes_wide(&y);
		self.state.update(&[x_f, y_f]);
		Ok(())
	}

	fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
		self.state.update(&[scalar]);
		Ok(())
	}
}

impl<R: Read, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>>
	TranscriptReadBuffer<R, C, Challenge255<C>> for PoseidonRead<R, C, P>
{
	fn init(reader: R) -> Self {
		let poseidon_state = PoseidonSponge::new();
		Self { reader, state: poseidon_state }
	}
}

/// PoseidonRead
pub struct PoseidonWrite<W: Write, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> {
	writer: W,
	state: PoseidonSponge<C::Scalar, WIDTH, P>,
}

impl<W: Write, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> Transcript<C, Challenge255<C>>
	for PoseidonWrite<W, C, P>
{
	fn squeeze_challenge(&mut self) -> Challenge255<C> {
		let res = self.state.squeeze();
		let result = to_wide(res.to_repr().as_ref());
		Challenge255::<C>::new(&result)
	}

	fn common_point(&mut self, point: C) -> io::Result<()> {
		let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::Other,
				"cannot write points at infinity to the transcript",
			)
		})?;
		let x = to_wide(coords.x().to_repr().as_ref());
		let y = to_wide(coords.y().to_repr().as_ref());
		let x_f = C::ScalarExt::from_bytes_wide(&x);
		let y_f = C::ScalarExt::from_bytes_wide(&y);
		self.state.update(&[x_f, y_f]);
		Ok(())
	}

	fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
		self.state.update(&[scalar]);
		Ok(())
	}
}

impl<W: Write, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>>
	TranscriptWriterBuffer<W, C, Challenge255<C>> for PoseidonWrite<W, C, P>
{
	fn init(writer: W) -> Self {
		let poseidon = PoseidonSponge::new();
		Self { writer, state: poseidon }
	}

	/// Conclude the interaction and return the output buffer (writer).
	fn finalize(self) -> W {
		self.writer
	}
}

impl<W: Write, C: CurveAffine, P: RoundParams<C::Scalar, WIDTH>> TranscriptWrite<C, Challenge255<C>>
	for PoseidonWrite<W, C, P>
{
	fn write_point(&mut self, point: C) -> io::Result<()> {
		self.common_point(point)?;
		let compressed = point.to_bytes();
		self.writer.write_all(compressed.as_ref())
	}

	fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
		self.common_scalar(scalar)?;
		let data = scalar.to_repr();
		self.writer.write_all(data.as_ref())
	}
}
