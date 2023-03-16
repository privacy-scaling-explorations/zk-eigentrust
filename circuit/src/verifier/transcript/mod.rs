use super::loader::{
	native::{NUM_BITS, NUM_LIMBS},
	Halo2Loader,
};
use crate::{
	integer::rns::RnsParams, params::RoundParams, poseidon::sponge::PoseidonSpongeChipset,
};
use halo2::{circuit::Layouter, halo2curves::CurveAffine};
use native::WIDTH;
use snark_verifier::util::transcript::Transcript;
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
	// TODO: Open a new region and assign a default value (0) to a cell, and save it
	// into PoseidonReadChipset struct

	/// Construct new PoseidonReadChipset
	pub fn new(reader: RD, loader: Halo2Loader<C, L, P>) -> Self {
		Self { reader, state: PoseidonSpongeChipset::new(), loader, _p: PhantomData }
	}
}

// TODO: Implement Transcript for PoseidonReadChipset
// TODO: Implement TranscriptRead for PoseidonReadChipset
