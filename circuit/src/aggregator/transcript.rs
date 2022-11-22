use std::marker::PhantomData;

use halo2wrong::curves::FieldExt;

use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
	params::RoundParams,
	poseidon::native::sponge::PoseidonSponge,
};

const WIDTH: usize = 5;
const NUM_LIMBS: usize = 4;
const NUM_BITS: usize = 68;

struct Transcript<W: FieldExt, N: FieldExt, P, R>
where
	P: RoundParams<N, WIDTH>,
	R: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	hasher: PoseidonSponge<N, WIDTH, P>,
	_wrong: PhantomData<W>,
	_params: PhantomData<P>,
	_rns: PhantomData<R>,
}

impl<W: FieldExt, N: FieldExt, P, R> Transcript<W, N, P, R>
where
	P: RoundParams<N, WIDTH>,
	R: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	fn new() -> Self {
		Self {
			hasher: PoseidonSponge::new(),
			_wrong: PhantomData,
			_params: PhantomData,
			_rns: PhantomData,
		}
	}

	fn common_scalar(&mut self, scalar: Integer<W, N, NUM_LIMBS, NUM_BITS, R>) {
		let native_scalar = R::compose(scalar.limbs);
		self.hasher.update(&[native_scalar]);
	}

	fn common_point(&mut self, point: EcPoint<W, N, NUM_LIMBS, NUM_BITS, R>) {
		let native_x = R::compose(point.x.limbs);
		let native_y = R::compose(point.x.limbs);
		self.hasher.update(&[native_x, native_y]);
	}

	fn squeeze_challange(&mut self) -> N {
		self.hasher.squeeze()
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn should_add_scalar_and_point_to_transcript() {}
}
