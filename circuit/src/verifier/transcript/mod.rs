use super::loader::{
	native::{NUM_BITS, NUM_LIMBS},
	Halo2LEcPoint, Halo2LScalar, LoaderConfig,
};
use crate::{
	ecc::AssignedPoint,
	integer::{native::Integer, rns::RnsParams, AssignedInteger},
	params::RoundParams,
	poseidon::sponge::PoseidonSpongeChipset,
	utils::to_wide,
	Chipset, RegionCtx,
};
use halo2::{
	arithmetic::{Field, FieldExt},
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::CurveAffine,
};
use native::WIDTH;
use snark_verifier::{
	util::{
		arithmetic::PrimeField,
		transcript::{Transcript, TranscriptRead},
	},
	Error as VerifierError,
};
use std::{
	io::{ErrorKind, Read},
	marker::PhantomData,
};

/// Native version of transcript
pub mod native;

/// PoseidonReadChipset structure
pub struct PoseidonReadChipset<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	reader: RD,
	state: PoseidonSpongeChipset<C::Scalar, WIDTH, R>,
	loader: LoaderConfig<C, L, P>,
	_p: PhantomData<P>,
}

impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R> PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Construct new PoseidonReadChipset
	pub fn new(reader: RD, loader: LoaderConfig<C, L, P>) -> Self {
		Self { reader, state: PoseidonSpongeChipset::new(), loader, _p: PhantomData }
	}

	/// Construct a new assigned zero value
	pub fn assigned_zero(loader: LoaderConfig<C, L, P>) -> AssignedCell<C::Scalar, C::Scalar> {
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

impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R> Transcript<C, LoaderConfig<C, L, P>>
	for PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	/// Returns [`LoaderConfig`].
	fn loader(&self) -> &LoaderConfig<C, L, P> {
		&self.loader
	}

	/// Squeeze a challenge.
	fn squeeze_challenge(&mut self) -> Halo2LScalar<C, L, P> {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let default = Self::assigned_zero(self.loader.clone());
		self.state.update(&[default]);
		let hasher = self.state.clone();
		let value = hasher
			.synthesize(
				&self.loader.common,
				&self.loader.poseidon_sponge,
				loader_ref.namespace(|| "squeeze_challenge"),
			)
			.unwrap();
		Halo2LScalar::new(value, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(
		&mut self, ec_point: &Halo2LEcPoint<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		let default = Self::assigned_zero(self.loader.clone());
		self.state.update(&[default]);
		let coords = Option::from((ec_point.inner.x.clone(), ec_point.inner.y.clone()))
			.ok_or_else(|| {
				VerifierError::Transcript(
					ErrorKind::Other,
					"cannot write points at infinity to the transcript".to_string(),
				)
			})?;
		self.state.update(&coords.0.limbs);
		self.state.update(&coords.1.limbs);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(
		&mut self, scalar: &Halo2LScalar<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		let default = Self::assigned_zero(self.loader.clone());
		self.state.update(&[default, scalar.inner.clone()]);

		Ok(())
	}
}

impl<RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
	TranscriptRead<C, LoaderConfig<C, L, P>> for PoseidonReadChipset<RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
{
	fn read_scalar(&mut self) -> Result<Halo2LScalar<C, L, P>, snark_verifier::Error> {
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
		let loader = self.loader.clone();
		let mut layouter = loader.layouter.lock().unwrap();
		let assigned_scalar = layouter
			.assign_region(
				|| "assign_scalar",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let scalar =
						ctx.assign_advice(self.loader.common.advice[0], Value::known(scalar))?;
					Ok(scalar)
				},
			)
			.unwrap();
		let assigned_lscalar = Halo2LScalar::new(assigned_scalar, self.loader.clone());
		Self::common_scalar(self, &assigned_lscalar)?;

		Ok(assigned_lscalar)
	}

	fn read_ec_point(&mut self) -> Result<Halo2LEcPoint<C, L, P>, snark_verifier::Error> {
		let mut compressed = [0; 256];
		self.reader.read_exact(compressed.as_mut()).map_err(|err| {
			VerifierError::Transcript(
				err.kind(),
				"invalid field element encoding in proof".to_string(),
			)
		})?;

		let mut limb_chunk = compressed.chunks(32);
		let mut x_limbs = [C::Scalar::default(); NUM_LIMBS];
		for i in 0..NUM_LIMBS {
			let bytes = to_wide(limb_chunk.next().unwrap());
			x_limbs[i] = C::Scalar::from_bytes_wide(&bytes);
		}

		let mut y_limbs = [C::Scalar::default(); NUM_LIMBS];
		for i in 0..NUM_LIMBS {
			let bytes = to_wide(limb_chunk.next().unwrap());
			y_limbs[i] = C::Scalar::from_bytes_wide(&bytes);
		}

		let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_limbs(x_limbs);
		let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_limbs(y_limbs);

		let loader = self.loader.clone();
		let mut layouter = loader.layouter.lock().unwrap();
		let assigned_coordinates = layouter
			.assign_region(
				|| "assign_coordinates",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut y_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						x_limbs[i] = Some(
							ctx.assign_advice(
								self.loader.common.advice[i],
								Value::known(x.limbs[i]),
							)
							.unwrap(),
						);
						y_limbs[i] = Some(
							ctx.assign_advice(
								self.loader.common.advice[i + NUM_LIMBS],
								Value::known(y.limbs[i]),
							)
							.unwrap(),
						);
					}
					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|x| x.unwrap())))
				},
			)
			.unwrap();

		let assigned_integer_x =
			AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(x, assigned_coordinates.0);
		let assigned_integer_y =
			AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(y, assigned_coordinates.1);

		let assigned_point = AssignedPoint::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
			assigned_integer_x, assigned_integer_y,
		);
		let loaded_point = Halo2LEcPoint::new(assigned_point, loader.clone());
		self.common_ec_point(&loaded_point)?;

		Ok(loaded_point)
	}
}

// TODO: Write tests comparing native and halo2 version
// - squeeze_challenge
// - common_ec_point
// - common_scalar
// - read_scalar
// - read_ec_point
