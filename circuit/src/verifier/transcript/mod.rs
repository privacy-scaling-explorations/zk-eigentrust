use super::loader::{
	native::{NUM_BITS, NUM_LIMBS},
	Halo2LEcPoint, Halo2LScalar, Halo2Loader,
};
use crate::{
	integer::rns::RnsParams,
	params::RoundParams,
	poseidon::{sponge::PoseidonSpongeChipset, PoseidonChipset},
	RegionCtx,
};
use halo2::{
	arithmetic::Field,
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::CurveAffine,
};
use native::WIDTH;
use snark_verifier::util::transcript::{Transcript, TranscriptRead};
use std::{io::Read, marker::PhantomData};

/// Native version of transcript
pub mod native;

// TODO: Add TranscriptRead<_, Halo2Loader> for PoseidonRead struct that uses
// PoseidonSpongeChipset

/// PoseidonReadChipset
pub struct PoseidonReadChipset<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	reader: RD,
	state: PoseidonSpongeChipset<C::Scalar, WIDTH, R>,
	loader: Halo2Loader<C, L, P>,
	_p: PhantomData<P>,
}

impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R> PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Construct new PoseidonReadChipset
	pub fn new(reader: RD, loader: Halo2Loader<C, L, P>) -> Self {
		Self { reader, state: PoseidonSpongeChipset::new(), loader, _p: PhantomData }
	}

	/// Construct a new assigned zero value
	pub fn assigned_zero(loader: Halo2Loader<C, L, P>) -> AssignedCell<C::Scalar, C::Scalar> {
		let mut layouter = loader.layouter.lock().unwrap();
		let assigned_zero = layouter
			.assign_region(
				|| "assigned_zero",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					Ok(ctx.assign_fixed(loader.common.fixed[0], C::Scalar::zero())?)
				},
			)
			.unwrap();
		assigned_zero
	}
}
/*
impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R> Transcript<C, Halo2Loader<C, L, P>>
	for PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	fn loader(&self) -> &Halo2Loader<C, L, P> {
		&self.loader
	}

	fn squeeze_challenge(&mut self) -> Halo2LScalar<C, L, P> {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let default = Self::assigned_zero(self.loader);
		self.state.update(default);
		let mut hasher = self.state.synthesize(
			&self.loader.common,
			&self.loader.poseidon_sponge,
			loader_ref.namespace(|| "squeeze_challenge"),
		);
	}

	fn common_ec_point(
		&mut self, ec_point: &Halo2LEcPoint<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		todo!()
	}

	fn common_scalar(
		&mut self, scalar: &Halo2LScalar<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		todo!()
	}
}

impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R> TranscriptRead<C, Halo2Loader<C, L, P>>
	for PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	fn read_scalar(&mut self) -> Result<Halo2LScalar<C, L, P>, snark_verifier::Error> {
		todo!()
	}

	fn read_ec_point(&mut self) -> Result<Halo2LEcPoint<C, L, P>, snark_verifier::Error> {
		todo!()
	}
}
*/
