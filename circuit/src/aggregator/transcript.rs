use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
	params::RoundParams,
	poseidon::native::sponge::PoseidonSponge,
};
use halo2wrong::{
	curves::{group::ff::PrimeField, Coordinates, CurveAffine, FieldExt},
	halo2::plonk::Error,
};
use std::{io::Read, marker::PhantomData};

const WIDTH: usize = 5;
const NUM_LIMBS: usize = 4;
const NUM_BITS: usize = 68;

struct Transcript<C: CurveAffine, I: Read, P, R>
where
	P: RoundParams<C::ScalarExt, WIDTH>,
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	hasher: PoseidonSponge<C::ScalarExt, WIDTH, P>,
	buffer: I,
	_params: PhantomData<P>,
	_rns: PhantomData<R>,
}

impl<C: CurveAffine, I: Read, P, R> Transcript<C, I, P, R>
where
	P: RoundParams<C::ScalarExt, WIDTH>,
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn new(buffer: I) -> Self {
		Self { hasher: PoseidonSponge::new(), buffer, _params: PhantomData, _rns: PhantomData }
	}

	fn common_scalar(&mut self, scalar: Integer<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>) {
		let native_scalar = R::compose(scalar.limbs);
		self.hasher.update(&[native_scalar]);
	}

	fn common_point(&mut self, point: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>) {
		let native_x = R::compose(point.x.limbs);
		let native_y = R::compose(point.x.limbs);
		self.hasher.update(&[native_x, native_y]);
	}

	fn squeeze_challange(&mut self) -> C::ScalarExt {
		self.hasher.squeeze()
	}

	fn read_scalar(&mut self) -> Result<C::ScalarExt, Error> {
		let mut data = <C::Scalar as PrimeField>::Repr::default();
		self.buffer.read_exact(data.as_mut())?;
		let scalar_opt: Option<C::ScalarExt> = C::Scalar::from_repr(data).into();
		let scalar = scalar_opt.ok_or(Error::Synthesis)?;
		self.hasher.update(&[scalar]);
		Ok(scalar)
	}

	fn read_point(&mut self) -> Result<C, Error> {
		let mut data = C::Repr::default();
		self.buffer.read_exact(data.as_mut())?;
		let point_opt: Option<C> = C::from_bytes(&data).into();
		let point = point_opt.ok_or(Error::Synthesis)?;
		let coord_opt: Option<Coordinates<C>> = point.coordinates().into();
		let coord = coord_opt.ok_or(Error::Synthesis)?;
		let x = Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>::from_w(*coord.x());
		let y = Integer::<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>::from_w(*coord.y());
		let native_x = R::compose(x.limbs);
		let native_y = R::compose(y.limbs);
		self.hasher.update(&[native_x, native_y]);
		Ok(point)
	}

	fn read_n_scalars(&mut self, n: usize) -> Result<Vec<C::ScalarExt>, Error> {
		(0..n).map(|_| self.read_scalar()).collect()
	}

	fn read_n_points(&mut self, n: usize) -> Result<Vec<C>, Error> {
		(0..n).map(|_| self.read_point()).collect()
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn should_add_scalar_and_point_to_transcript() {}
}
