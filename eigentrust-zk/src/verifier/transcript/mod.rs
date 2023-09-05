use super::loader::{
	native::{NUM_BITS, NUM_LIMBS},
	Halo2LEcPoint, Halo2LScalar, LoaderConfig,
};
use crate::{
	ecc::same_curve::AssignedEcPoint,
	integer::{native::Integer, AssignedInteger},
	params::{ecc::EccParams, rns::RnsParams},
	FieldExt, RegionCtx, SpongeHasherChipset,
};
use halo2::{
	circuit::{Layouter, Region, Value},
	halo2curves::{Coordinates, CurveAffine},
};
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

/// Native version of the transcript
pub mod native;

/// TranscriptReadChipset structure
pub struct TranscriptReadChipset<
	'a,
	RD: Read,
	C: CurveAffine,
	L: Layouter<C::Scalar>,
	P,
	const WIDTH: usize,
	S,
	EC,
> where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Reader
	reader: Option<RD>,
	// PoseidonSponge
	state: S,
	// Loader
	loader: LoaderConfig<'a, C, L, P, WIDTH, S, EC>,
	// PhantomData
	_p: PhantomData<P>,
}

impl<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, const WIDTH: usize, S, EC>
	TranscriptReadChipset<'a, RD, C, L, P, WIDTH, S, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new PoseidonReadChipset
	pub fn new(reader: Option<RD>, loader: LoaderConfig<'a, C, L, P, WIDTH, S, EC>) -> Self {
		let sponge = {
			let mut layouter_mut = loader.layouter.borrow_mut();
			S::init(&loader.common, layouter_mut.namespace(|| "stateful_sponge")).unwrap()
		};

		Self { reader, state: sponge, loader, _p: PhantomData }
	}
}

impl<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, const WIDTH: usize, S, EC>
	Transcript<C, LoaderConfig<'a, C, L, P, WIDTH, S, EC>>
	for TranscriptReadChipset<'a, RD, C, L, P, WIDTH, S, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns [`LoaderConfig`].
	fn loader(&self) -> &LoaderConfig<'a, C, L, P, WIDTH, S, EC> {
		&self.loader
	}

	/// Squeeze a challenge.
	fn squeeze_challenge(&mut self) -> Halo2LScalar<'a, C, L, P, WIDTH, S, EC> {
		let result = {
			let mut loader_ref = self.loader.layouter.borrow_mut();
			let res = self
				.state
				.squeeze(
					&self.loader.common,
					&self.loader.sponge,
					loader_ref.namespace(|| "squeeze_challenge"),
				)
				.unwrap();
			res
		};

		Halo2LScalar::new(result, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(
		&mut self, ec_point: &Halo2LEcPoint<C, L, P, WIDTH, S, EC>,
	) -> Result<(), snark_verifier::Error> {
		self.state.update(&ec_point.inner.x.limbs);
		self.state.update(&ec_point.inner.y.limbs);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(
		&mut self, scalar: &Halo2LScalar<C, L, P, WIDTH, S, EC>,
	) -> Result<(), snark_verifier::Error> {
		self.state.update(&[scalar.inner.clone()]);

		Ok(())
	}
}

impl<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, const WIDTH: usize, S, EC>
	TranscriptRead<C, LoaderConfig<'a, C, L, P, WIDTH, S, EC>>
	for TranscriptReadChipset<'a, RD, C, L, P, WIDTH, S, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Read a scalar.
	fn read_scalar(&mut self) -> Result<Halo2LScalar<'a, C, L, P, WIDTH, S, EC>, VerifierError> {
		// Taking out reader from Value for a proper error handling
		let scalar = self.reader.as_mut().map_or_else(
			|| Ok(Value::unknown()),
			|reader| {
				let mut data = <C::Scalar as PrimeField>::Repr::default();
				let res = reader.read_exact(data.as_mut());

				if let Err(e) = res {
					return Err(VerifierError::Transcript(
						e.kind(),
						"invalid field element encoding in proof - halo2".to_string(),
					));
				}

				let scalar_opt = Option::<C::Scalar>::from(C::Scalar::from_repr(data));
				if scalar_opt.is_none() {
					return Err(VerifierError::Transcript(
						ErrorKind::Other,
						"invalid field element encoding in proof - halo2".to_string(),
					));
				}

				let scalar = scalar_opt.unwrap();
				Ok(Value::known(scalar))
			},
		)?;

		let assigned_scalar = {
			let mut layouter = self.loader.layouter.borrow_mut();
			layouter
				.assign_region(
					|| "assign_scalar",
					|region: Region<'_, C::Scalar>| {
						let mut ctx = RegionCtx::new(region, 0);
						let scalar = ctx.assign_advice(self.loader.common.advice[0], scalar)?;
						Ok(scalar)
					},
				)
				.unwrap()
		};
		let assigned_lscalar = Halo2LScalar::new(assigned_scalar, self.loader.clone());
		self.common_scalar(&assigned_lscalar)?;

		Ok(assigned_lscalar)
	}

	/// Read an elliptic curve point.
	fn read_ec_point(&mut self) -> Result<Halo2LEcPoint<'a, C, L, P, WIDTH, S, EC>, VerifierError> {
		// Taking out reader from Value for a proper error handling
		let (x, y, x_limbs, y_limbs) = self.reader.as_mut().map_or_else(
			|| {
				Ok((
					Integer::default(),
					Integer::default(),
					[Value::unknown(); NUM_LIMBS],
					[Value::unknown(); NUM_LIMBS],
				))
			},
			|reader| {
				let mut compressed = C::Repr::default();
				let res = reader.read_exact(compressed.as_mut());
				if let Err(e) = res {
					return Err(VerifierError::Transcript(
						e.kind(),
						"invalid field element encoding in proof - halo2".to_string(),
					));
				}

				let point_opt: Option<C> = Option::from(C::from_bytes(&compressed));
				if point_opt.is_none() {
					return Err(VerifierError::Transcript(
						ErrorKind::Other,
						"invalid point encoding in proof - halo2".to_string(),
					));
				}

				let coordinates_opt = Option::from(point_opt.unwrap().coordinates());
				if coordinates_opt.is_none() {
					return Err(VerifierError::Transcript(
						ErrorKind::Other,
						"invalid point coordinates in proof - halo2".to_string(),
					));
				}
				let coordinates: Coordinates<C> = coordinates_opt.unwrap();
				let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.x());
				let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.y());

				let mut x_limbs: [Value<C::Scalar>; NUM_LIMBS] = [Value::unknown(); NUM_LIMBS];
				let mut y_limbs: [Value<C::Scalar>; NUM_LIMBS] = [Value::unknown(); NUM_LIMBS];
				for i in 0..NUM_LIMBS {
					x_limbs[i] = Value::known(x.limbs[i]);
				}
				for i in 0..NUM_LIMBS {
					y_limbs[i] = Value::known(y.limbs[i]);
				}

				Ok((x, y, x_limbs, y_limbs))
			},
		)?;

		let loader = self.loader.clone();
		let (assigned_x, assigned_y) = {
			let mut layouter = loader.layouter.borrow_mut();
			layouter
				.assign_region(
					|| "assign_coordinates",
					|region: Region<'_, C::Scalar>| {
						let mut ctx = RegionCtx::new(region, 0);
						let mut assigned_x_limbs = Vec::new();
						let mut assigned_y_limbs = Vec::new();
						for i in 0..NUM_LIMBS {
							let assigned_x_limb = ctx
								.assign_advice(self.loader.common.advice[i], x_limbs[i])
								.unwrap();
							assigned_x_limbs.push(assigned_x_limb);
						}

						ctx.next();

						for i in 0..NUM_LIMBS {
							let assigned_y_limb = ctx
								.assign_advice(self.loader.common.advice[i], y_limbs[i])
								.unwrap();
							assigned_y_limbs.push(assigned_y_limb);
						}
						Ok((assigned_x_limbs, assigned_y_limbs))
					},
				)
				.unwrap()
		};

		let assigned_integer_x =
			AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(x, assigned_x.try_into().unwrap());
		let assigned_integer_y =
			AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(y, assigned_y.try_into().unwrap());

		let assigned_point = AssignedEcPoint::<_, NUM_LIMBS, NUM_BITS, P>::new(
			assigned_integer_x, assigned_integer_y,
		);
		let loaded_point = Halo2LEcPoint::new(assigned_point, loader.clone());
		self.common_ec_point(&loaded_point)?;

		Ok(loaded_point)
	}
}

#[cfg(test)]
mod test {
	use super::{native::NativeTranscriptRead, LoaderConfig, TranscriptReadChipset};
	use crate::{
		circuits::{FullRoundHasher, PartialRoundHasher},
		ecc::{
			same_curve::{native::EcPoint, AssignedEcPoint, UnassignedEcPoint},
			AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
			EccUnreducedLadderConfig,
		},
		gadgets::{
			absorb::AbsorbChip,
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		halo2::transcript::TranscriptWriterBuffer,
		integer::{
			native::Integer, AssignedInteger, IntegerAddChip, IntegerDivChip, IntegerMulChip,
			IntegerReduceChip, IntegerSubChip, UnassignedInteger,
		},
		params::hasher::poseidon_bn254_5x5::Params,
		params::{ecc::bn254::Bn254Params, rns::bn256::Bn256_4_68},
		poseidon::{
			native::sponge::PoseidonSponge,
			sponge::{PoseidonSpongeConfig, StatefulSpongeChipset},
			PoseidonConfig,
		},
		verifier::{
			loader::{
				native::{NUM_BITS, NUM_LIMBS},
				Halo2LEcPoint, Halo2LScalar,
			},
			transcript::native::{NativeTranscriptWrite, WIDTH},
		},
		Chip, CommonConfig, RegionCtx, UnassignedValue,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Fq, Fr, G1Affine},
			group::GroupEncoding,
			CurveAffine,
		},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	use rand::thread_rng;
	use snark_verifier::{
		loader::native::NativeLoader as NativeSVLoader,
		util::transcript::{Transcript, TranscriptRead, TranscriptWrite},
	};
	use std::io::Write;

	type C = G1Affine;
	type P = Bn256_4_68;
	type S = StatefulSpongeChipset<Scalar, WIDTH, Params>;
	type NativeH = PoseidonSponge<Scalar, WIDTH, Params>;
	type Scalar = Fr;
	type Base = Fq;
	type EC = Bn254Params;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
		poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
		ecc_add: EccAddConfig,
		aux: AuxConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<Scalar>) -> Self {
			let common = CommonConfig::new(meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);

			let full_round_selector = FullRoundHasher::configure(&common, meta);
			let partial_round_selector = PartialRoundHasher::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let absorb_selector = AbsorbChip::<Scalar, WIDTH>::configure(&common, meta);
			let poseidon_sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			let bits2num = Bits2NumChip::configure(&common, meta);

			let int_red =
				IntegerReduceChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_add =
				IntegerAddChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_sub =
				IntegerSubChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_mul =
				IntegerMulChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_div =
				IntegerDivChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);

			let ecc_ladder = EccUnreducedLadderConfig::new(int_add, int_sub, int_mul, int_div);
			let ecc_add = EccAddConfig::new(int_red, int_sub, int_mul, int_div);
			let ecc_double = EccDoubleConfig::new(int_red, int_add, int_sub, int_mul, int_div);
			let ecc_table_select = EccTableSelectConfig::new(main.clone());
			let ecc_mul_scalar = EccMulConfig::new(
				ecc_ladder,
				ecc_add.clone(),
				ecc_double.clone(),
				ecc_table_select,
				bits2num,
			);
			let aux = AuxConfig::new(ecc_double);
			TestConfig { common, main, poseidon_sponge, ecc_mul_scalar, ecc_add, aux }
		}
	}

	#[derive(Clone)]
	struct TestSqueezeCircuit;

	impl Circuit<Scalar> for TestSqueezeCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			TestSqueezeCircuit
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let res = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge,
				);
				let reader = Vec::new();
				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					Some(reader.as_slice()),
					loader,
				);
				let res = poseidon_read.squeeze_challenge();
				res.inner
			};

			layouter.constrain_instance(res.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_squeeze_challenge() {
		// Test squeeze challenge
		let reader = Vec::new();
		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);

		let res = poseidon_read.squeeze_challenge();
		let k = 7;
		let prover = MockProver::run(k, &TestSqueezeCircuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestCommonEcPointCircuit {
		ec_point: UnassignedEcPoint<G1Affine, NUM_LIMBS, NUM_BITS, P, EC>,
	}

	impl TestCommonEcPointCircuit {
		fn new(ec_point: EcPoint<G1Affine, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
			let unassigned_x = UnassignedInteger::new(
				ec_point.x.clone(),
				ec_point.x.limbs.map(|x| Value::known(x)),
			);
			let unassigned_y = UnassignedInteger::new(
				ec_point.y.clone(),
				ec_point.y.limbs.map(|y| Value::known(y)),
			);

			let unassigned_ec_point = UnassignedEcPoint::new(unassigned_x, unassigned_y);
			Self { ec_point: unassigned_ec_point }
		}
	}

	impl Circuit<Scalar> for TestCommonEcPointCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { ec_point: UnassignedEcPoint::without_witnesses() }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let x = &self.ec_point.x;
			let y = &self.ec_point.y;

			let assigned_coordinates = layouter.assign_region(
				|| "assign",
				|region: Region<'_, Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut y_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						x_limbs[i] = Some(ctx.assign_advice(config.common.advice[i], x.limbs[i])?);
						y_limbs[i] = Some(
							ctx.assign_advice(config.common.advice[i + NUM_LIMBS], y.limbs[i])?,
						);
					}
					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|x| x.unwrap())))
				},
			)?;

			let res = {
				let loader_layouter = layouter.namespace(|| "loader");
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					loader_layouter,
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let assigned_integer_x = AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
					x.integer.clone(),
					assigned_coordinates.0,
				);
				let assigned_integer_y = AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
					y.integer.clone(),
					assigned_coordinates.1,
				);

				let assigned_point = AssignedEcPoint::<_, NUM_LIMBS, NUM_BITS, P>::new(
					assigned_integer_x, assigned_integer_y,
				);
				let ec_point = Halo2LEcPoint::new(assigned_point, loader.clone());

				let reader = Vec::new();
				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					Some(reader.as_slice()),
					loader,
				);
				poseidon_read.common_ec_point(&ec_point).unwrap();

				let res = poseidon_read.squeeze_challenge();

				res.inner
			};

			layouter.constrain_instance(res.clone().cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_common_ec_point() {
		// Test common ec point
		let reader = Vec::new();
		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);
		let rng = &mut thread_rng();
		let ec_point = C::random(rng);
		poseidon_read.common_ec_point(&ec_point).unwrap();

		let coordinates = ec_point.coordinates().unwrap();
		let x_integer = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.x());
		let y_integer = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.y());
		let ec_point = EcPoint::new(x_integer, y_integer);

		let res = poseidon_read.squeeze_challenge();
		let circuit = TestCommonEcPointCircuit::new(ec_point);

		let k = 8;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestCommonScalarCircuit {
		scalar: Value<Scalar>,
	}

	impl TestCommonScalarCircuit {
		fn new(scalar: Scalar) -> Self {
			Self { scalar: Value::known(scalar) }
		}
	}

	impl Circuit<Scalar> for TestCommonScalarCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { scalar: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let res = {
				let assigned_scalar = layouter
					.assign_region(
						|| "assign_scalar",
						|region: Region<'_, Scalar>| {
							let mut ctx = RegionCtx::new(region, 0);
							let scalar = ctx.assign_advice(config.common.advice[0], self.scalar)?;
							Ok(scalar)
						},
					)
					.unwrap();

				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);
				let scalar = Halo2LScalar::new(assigned_scalar, loader.clone());
				let reader = Vec::new();
				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					Some(reader.as_slice()),
					loader,
				);
				poseidon_read.common_scalar(&scalar).unwrap();

				let res = poseidon_read.squeeze_challenge();
				res.inner
			};

			layouter.constrain_instance(res.clone().cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_common_scalar() {
		// Test common scalar
		let reader = Vec::new();
		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);
		let rng = &mut thread_rng();
		let scalar = Scalar::random(rng);
		poseidon_read.common_scalar(&scalar).unwrap();

		let res = poseidon_read.state.squeeze();
		let circuit = TestCommonScalarCircuit::new(scalar);
		let k = 7;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestReadScalarCircuit {
		reader: Option<Vec<u8>>,
	}

	impl TestReadScalarCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader: Some(reader) }
		}
	}

	impl Circuit<Scalar> for TestReadScalarCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { reader: None }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let scalar = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					self.reader.as_ref().map(|x| x.as_slice()),
					loader,
				);
				let res = poseidon_read.read_scalar().unwrap();
				res.inner
			};

			layouter.constrain_instance(scalar.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_read_scalar() {
		// Test read scalar
		let rng = &mut thread_rng();
		let random = Scalar::random(rng);
		let mut reader = Vec::new();
		reader.write_all(random.to_bytes().as_slice()).unwrap();
		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);

		let res = poseidon_read.read_scalar().unwrap();
		let circuit = TestReadScalarCircuit::new(reader);
		let k = 6;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestReadEcPointCircuit {
		reader: Option<Vec<u8>>,
	}

	impl TestReadEcPointCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader: Some(reader) }
		}
	}

	impl Circuit<Scalar> for TestReadEcPointCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { reader: None }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let (x_limbs, y_limbs) = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					self.reader.as_ref().map(Vec::as_slice),
					loader,
				);
				let res = poseidon_read.read_ec_point().unwrap();
				let x_limbs = res.inner.clone().x.limbs;
				let y_limbs = res.inner.clone().y.limbs;

				(x_limbs, y_limbs)
			};

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(x_limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					y_limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}
			Ok(())
		}
	}

	#[test]
	fn test_read_ec_point() {
		// Test read ec point
		let rng = &mut thread_rng();
		let random = C::random(rng).to_bytes();
		let mut reader = Vec::new();
		reader.write_all(random.as_ref()).unwrap();

		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);

		let res = poseidon_read.read_ec_point().unwrap();
		let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.x);
		let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.y);

		let mut p_ins = Vec::new();
		p_ins.extend(x.limbs);
		p_ins.extend(y.limbs);
		let circuit = TestReadEcPointCircuit::new(reader);
		let k = 6;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestReadMultipleEcPointCircuit {
		reader: Option<Vec<u8>>,
	}

	impl TestReadMultipleEcPointCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader: Some(reader) }
		}
	}

	impl Circuit<Scalar> for TestReadMultipleEcPointCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { reader: None }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let (x1_limbs, y1_limbs, scalar1, x2_limbs, y2_limbs, scalar2) = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					self.reader.as_ref().map(|x| x.as_slice()),
					loader,
				);

				let res = poseidon_read.read_ec_point().unwrap();
				let x1_limbs = res.inner.clone().x.limbs;
				let y1_limbs = res.inner.clone().y.limbs;

				let res = poseidon_read.read_scalar().unwrap();
				let scalar1 = res.inner;

				let res = poseidon_read.read_ec_point().unwrap();
				let x2_limbs = res.inner.clone().x.limbs;
				let y2_limbs = res.inner.clone().y.limbs;

				let res = poseidon_read.read_scalar().unwrap();
				let scalar2 = res.inner;

				(x1_limbs, y1_limbs, scalar1, x2_limbs, y2_limbs, scalar2)
			};

			let mut i = 0;
			for j in 0..NUM_LIMBS {
				layouter.constrain_instance(x1_limbs[j].cell(), config.common.instance, i)?;
				i += 1;
			}
			for j in 0..NUM_LIMBS {
				layouter.constrain_instance(y1_limbs[j].cell(), config.common.instance, i)?;
				i += 1;
			}

			layouter.constrain_instance(scalar1.cell(), config.common.instance, i)?;
			i += 1;

			for j in 0..NUM_LIMBS {
				layouter.constrain_instance(x2_limbs[j].cell(), config.common.instance, i)?;
				i += 1;
			}
			for j in 0..NUM_LIMBS {
				layouter.constrain_instance(y2_limbs[j].cell(), config.common.instance, i)?;
				i += 1;
			}

			layouter.constrain_instance(scalar2.cell(), config.common.instance, i)?;

			Ok(())
		}
	}

	#[test]
	fn test_read_multiple_ec_point() {
		// Test read ec point
		let rng = &mut thread_rng();
		let mut reader = Vec::new();
		for _ in 0..2 {
			let random = C::random(rng.clone()).to_bytes();
			let scalar = Scalar::random(rng.clone());
			reader.write_all(random.as_ref()).unwrap();
			reader.write_all(scalar.to_bytes().as_slice()).unwrap();
		}
		let mut poseidon_read =
			NativeTranscriptRead::<_, G1Affine, Bn256_4_68, PoseidonSponge<Fr, 5, Params>>::new(
				reader.as_slice(),
				NativeSVLoader,
			);

		let mut p_ins = Vec::new();
		let res = poseidon_read.read_ec_point().unwrap();
		let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.x);
		let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.y);
		p_ins.extend(x.limbs);
		p_ins.extend(y.limbs);

		let res = poseidon_read.read_scalar().unwrap();
		p_ins.push(res);

		let res = poseidon_read.read_ec_point().unwrap();
		let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.x);
		let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.y);
		p_ins.extend(x.limbs);
		p_ins.extend(y.limbs);

		let res = poseidon_read.read_scalar().unwrap();
		p_ins.push(res);

		let circuit = TestReadMultipleEcPointCircuit::new(reader);
		let k = 6;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestSqueezeChallengeCircuit {
		reader: Option<Vec<u8>>,
	}

	impl TestSqueezeChallengeCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader: Some(reader) }
		}
	}

	impl Circuit<Scalar> for TestSqueezeChallengeCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { reader: None }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let res = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					self.reader.as_ref().map(|x| x.as_slice()),
					loader,
				);

				poseidon_read.read_ec_point().unwrap();
				poseidon_read.read_scalar().unwrap();
				poseidon_read.read_ec_point().unwrap();
				poseidon_read.read_scalar().unwrap();

				let res = poseidon_read.squeeze_challenge();
				res.inner
			};

			layouter.constrain_instance(res.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_squeeze_challange() {
		// Test read ec point
		let rng = &mut thread_rng();
		let mut reader = Vec::new();
		for _ in 0..2 {
			let random = C::random(rng.clone()).to_bytes();
			let scalar = Scalar::random(rng.clone());
			reader.write_all(random.as_ref()).unwrap();
			reader.write_all(scalar.to_bytes().as_slice()).unwrap();
		}
		let mut poseidon_read = NativeTranscriptRead::<_, G1Affine, Bn256_4_68, NativeH>::new(
			reader.as_slice(),
			NativeSVLoader,
		);

		poseidon_read.read_ec_point().unwrap();
		poseidon_read.read_scalar().unwrap();
		poseidon_read.read_ec_point().unwrap();
		poseidon_read.read_scalar().unwrap();

		let res = poseidon_read.squeeze_challenge();

		let circuit = TestSqueezeChallengeCircuit::new(reader);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestWriteReadCircuit {
		reader: Option<Vec<u8>>,
	}

	impl TestWriteReadCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader: Some(reader) }
		}
	}

	impl Circuit<Scalar> for TestWriteReadCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { reader: None }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let res = {
				let loader = LoaderConfig::<C, _, P, WIDTH, S, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.ecc_add,
					config.aux,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = TranscriptReadChipset::<_, C, _, P, WIDTH, S, EC>::new(
					self.reader.as_ref().map(|x| x.as_slice()),
					loader,
				);

				poseidon_read.read_scalar().unwrap();
				poseidon_read.read_ec_point().unwrap();
				poseidon_read.read_scalar().unwrap();
				poseidon_read.read_ec_point().unwrap();

				let res = poseidon_read.squeeze_challenge();
				res.inner
			};

			layouter.constrain_instance(res.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_write_read() {
		// Test read scalar
		let rng = &mut thread_rng();

		let random_scalar1 = Scalar::random(rng.clone());
		let random_ec1 = C::random(rng.clone());
		let random_scalar2 = Scalar::random(rng.clone());
		let random_ec2 = C::random(rng.clone());

		let mut poseidon_write =
			NativeTranscriptWrite::<_, G1Affine, Bn256_4_68, NativeH>::init(Vec::new());

		poseidon_write.write_scalar(random_scalar1).unwrap();
		poseidon_write.write_ec_point(random_ec1).unwrap();
		poseidon_write.write_scalar(random_scalar2).unwrap();
		poseidon_write.write_ec_point(random_ec2).unwrap();

		let res = poseidon_write.squeeze_challenge();
		let proof = poseidon_write.finalize();

		let circuit = TestWriteReadCircuit::new(proof);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
