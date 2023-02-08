use halo2::{
	halo2curves::{group::ff::Field, CurveAffine},
	transcript::{Challenge255, EncodedChallenge, Transcript, TranscriptRead},
};
use std::{io, marker::PhantomData};

/// PoseidonRead
pub struct PoseidonRead<C: CurveAffine>(PhantomData<C>);

impl<C: CurveAffine> TranscriptRead<C, Challenge255<C>> for PoseidonRead<C> {
	fn read_point(&mut self) -> io::Result<C> {
		Ok(C::default())
	}

	fn read_scalar(&mut self) -> io::Result<C::Scalar> {
		Ok(C::Scalar::zero())
	}
}

impl<C: CurveAffine> Transcript<C, Challenge255<C>> for PoseidonRead<C> {
	fn squeeze_challenge(&mut self) -> Challenge255<C> {
		let result: [u8; 64] = [0; 64];
		Challenge255::<C>::new(&result)
	}

	fn common_point(&mut self, point: C) -> io::Result<()> {
		Ok(())
	}

	fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
		Ok(())
	}
}
