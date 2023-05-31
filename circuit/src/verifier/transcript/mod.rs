use super::loader::{
	native::{NUM_BITS, NUM_LIMBS},
	Halo2LEcPoint, Halo2LScalar, LoaderConfig,
};
use crate::{
	ecc::AssignedPoint,
	integer::{native::Integer, AssignedInteger},
	params::RoundParams,
	poseidon::sponge::StatefulSpongeChipset,
	rns::RnsParams,
	FieldExt, RegionCtx,
};
use halo2::{
	circuit::{Layouter, Region, Value},
	halo2curves::{Coordinates, CurveAffine},
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
	fmt::Debug,
	io::{ErrorKind, Read},
	marker::PhantomData,
};

/// Native version of the transcript
pub mod native;

/// PoseidonReadChipset structure
pub struct PoseidonReadChipset<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Reader
	reader: Option<RD>,
	// PoseidonSponge
	sponge_hasher: StatefulSpongeChipset<C::Scalar, WIDTH, R>,
	// Loader
	loader: LoaderConfig<'a, C, L, P>,
	// PhantomData
	_p: PhantomData<P>,
}

impl<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
	PoseidonReadChipset<'a, RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new PoseidonReadChipset
	pub fn new(reader: Option<RD>, loader: LoaderConfig<'a, C, L, P>) -> Self {
		let sponge = {
			let mut layouter_mut = loader.layouter.borrow_mut();
			StatefulSpongeChipset::init(
				&loader.common,
				layouter_mut.namespace(|| "stateful_sponge"),
			)
			.unwrap()
		};

		Self { reader, sponge_hasher: sponge, loader, _p: PhantomData }
	}
}

impl<'a, RD: Read, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
	Transcript<C, LoaderConfig<'a, C, L, P>> for PoseidonReadChipset<'a, RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns [`LoaderConfig`].
	fn loader(&self) -> &LoaderConfig<'a, C, L, P> {
		&self.loader
	}

	/// Squeeze a challenge.
	fn squeeze_challenge(&mut self) -> Halo2LScalar<'a, C, L, P> {
		let result = {
			let mut loader_ref = self.loader.layouter.borrow_mut();
			let res = self
				.sponge_hasher
				.squeeze(
					&self.loader.common,
					&self.loader.poseidon_sponge,
					loader_ref.namespace(|| "squeeze_challenge"),
				)
				.unwrap();
			res
		};

		Halo2LScalar::new(result, self.loader.clone())
	}

	/// Update with an elliptic curve point.
	fn common_ec_point(
		&mut self, ec_point: &Halo2LEcPoint<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		self.sponge_hasher.update(&ec_point.inner.x.limbs);
		self.sponge_hasher.update(&ec_point.inner.y.limbs);

		Ok(())
	}

	/// Update with a scalar.
	fn common_scalar(
		&mut self, scalar: &Halo2LScalar<C, L, P>,
	) -> Result<(), snark_verifier::Error> {
		self.sponge_hasher.update(&[scalar.inner.clone()]);

		Ok(())
	}
}

impl<'a, RD: Read + Debug, C: CurveAffine, L: Layouter<C::Scalar>, P, R>
	TranscriptRead<C, LoaderConfig<'a, C, L, P>> for PoseidonReadChipset<'a, RD, C, L, P, R>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	R: RoundParams<C::Scalar, WIDTH>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Read a scalar.
	fn read_scalar(&mut self) -> Result<Halo2LScalar<'a, C, L, P>, VerifierError> {
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
				if let None = scalar_opt {
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
	fn read_ec_point(&mut self) -> Result<Halo2LEcPoint<'a, C, L, P>, VerifierError> {
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
				if let None = point_opt {
					return Err(VerifierError::Transcript(
						ErrorKind::Other,
						"invalid point encoding in proof - halo2".to_string(),
					));
				}

				let coordinates_opt = Option::from(point_opt.unwrap().coordinates());
				if let None = coordinates_opt {
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

		let assigned_point = AssignedPoint::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
			assigned_integer_x, assigned_integer_y,
		);
		let loaded_point = Halo2LEcPoint::new(assigned_point, loader.clone());
		self.common_ec_point(&loaded_point)?;

		Ok(loaded_point)
	}
}

#[cfg(test)]
mod test {
	use super::{native::PoseidonRead, LoaderConfig, PoseidonReadChipset};
	use crate::{
		circuit::{FullRoundHasher, PartialRoundHasher},
		ecc::{
			AssignedPoint, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
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
			IntegerReduceChip, IntegerSubChip,
		},
		params::poseidon_bn254_5x5::Params,
		poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
		rns::bn256::Bn256_4_68,
		verifier::{
			loader::{
				native::{NUM_BITS, NUM_LIMBS},
				Halo2LEcPoint, Halo2LScalar,
			},
			transcript::native::{PoseidonWrite, WIDTH},
		},
		Chip, CommonConfig, RegionCtx,
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
	type R = Params;
	type Scalar = Fr;
	type Base = Fq;
	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
		poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
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
			let poseidon_sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

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

			let ladder = EccUnreducedLadderConfig::new(int_add, int_sub, int_mul, int_div);
			let add = EccAddConfig::new(int_red, int_sub, int_mul, int_div);
			let double = EccDoubleConfig::new(int_red, int_add, int_sub, int_mul, int_div);
			let table_select = EccTableSelectConfig::new(main.clone());
			let ecc_mul_scalar = EccMulConfig::new(ladder, add, double, table_select, bits2num);
			TestConfig { common, main, poseidon_sponge, ecc_mul_scalar }
		}
	}

	#[derive(Clone)]
	struct TestCommonEcPointCircuit {
		ec_point: C,
	}

	impl TestCommonEcPointCircuit {
		fn new(ec_point: C) -> Self {
			Self { ec_point }
		}
	}

	impl Circuit<Scalar> for TestCommonEcPointCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let coordinates = self.ec_point.coordinates().unwrap();

			let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.x());
			let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(*coordinates.y());

			let assigned_coordinates = layouter
				.assign_region(
					|| "assign",
					|region: Region<'_, Scalar>| {
						let mut ctx = RegionCtx::new(region, 0);
						let mut x_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
							[(); NUM_LIMBS].map(|_| None);
						let mut y_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
							[(); NUM_LIMBS].map(|_| None);
						for i in 0..NUM_LIMBS {
							x_limbs[i] = Some(
								ctx.assign_advice(
									config.common.advice[i],
									Value::known(x.limbs[i]),
								)
								.unwrap(),
							);
							y_limbs[i] = Some(
								ctx.assign_advice(
									config.common.advice[i + NUM_LIMBS],
									Value::known(y.limbs[i]),
								)
								.unwrap(),
							);
						}
						Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|x| x.unwrap())))
					},
				)
				.unwrap();

			let res = {
				let loader_layouter = layouter.namespace(|| "loader");
				let loader = LoaderConfig::<C, _, P>::new(
					loader_layouter,
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let assigned_integer_x = AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
					x.clone(),
					assigned_coordinates.0,
				);
				let assigned_integer_y = AssignedInteger::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
					y.clone(),
					assigned_coordinates.1,
				);

				let assigned_point = AssignedPoint::<_, _, NUM_LIMBS, NUM_BITS, P>::new(
					assigned_integer_x, assigned_integer_y,
				);
				let ec_point = Halo2LEcPoint::new(assigned_point, loader.clone());

				let reader = Vec::new();
				let mut poseidon_read =
					PoseidonReadChipset::<_, C, _, P, R>::new(Some(reader.as_slice()), loader);
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
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);
		let rng = &mut thread_rng();
		let ec_point = C::random(rng);
		poseidon_read.common_ec_point(&ec_point).unwrap();

		let res = poseidon_read.squeeze_challenge();
		let circuit = TestCommonEcPointCircuit::new(ec_point);
		let k = 8;
		let prover = MockProver::run(k, &circuit, vec![vec![res]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestCommonScalarCircuit {
		scalar: Scalar,
	}

	impl TestCommonScalarCircuit {
		fn new(scalar: Scalar) -> Self {
			Self { scalar }
		}
	}

	impl Circuit<Scalar> for TestCommonScalarCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
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
							let scalar = ctx.assign_advice(
								config.common.advice[0],
								Value::known(self.scalar),
							)?;
							Ok(scalar)
						},
					)
					.unwrap();

				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);
				let scalar = Halo2LScalar::new(assigned_scalar, loader.clone());
				let reader = Vec::new();
				let mut poseidon_read =
					PoseidonReadChipset::<_, C, _, P, R>::new(Some(reader.as_slice()), loader);
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
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);
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
		reader: Vec<u8>,
	}

	impl TestReadScalarCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader }
		}
	}

	impl Circuit<Scalar> for TestReadScalarCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let scalar = {
				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read =
					PoseidonReadChipset::<_, C, _, P, R>::new(Some(self.reader.as_slice()), loader);
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
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);

		let res = poseidon_read.read_scalar().unwrap();
		let circuit = TestReadScalarCircuit::new(reader);
		let k = 7;
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
				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = PoseidonReadChipset::<_, C, _, P, R>::new(
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
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);

		let res = poseidon_read.read_ec_point().unwrap();
		let x = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.x);
		let y = Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(res.y);

		let mut p_ins = Vec::new();
		p_ins.extend(x.limbs);
		p_ins.extend(y.limbs);
		let circuit = TestReadEcPointCircuit::new(reader);
		let k = 7;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestReadMultipleEcPointCircuit {
		reader: Vec<u8>,
	}

	impl TestReadMultipleEcPointCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader }
		}
	}

	impl Circuit<Scalar> for TestReadMultipleEcPointCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let (x1_limbs, y1_limbs, scalar1, x2_limbs, y2_limbs, scalar2) = {
				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read =
					PoseidonReadChipset::<_, C, _, P, R>::new(Some(self.reader.as_slice()), loader);

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
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);

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
		let k = 7;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestSqueezeChallengeCircuit {
		reader: Vec<u8>,
	}

	impl TestSqueezeChallengeCircuit {
		fn new(reader: Vec<u8>) -> Self {
			Self { reader }
		}
	}

	impl Circuit<Scalar> for TestSqueezeChallengeCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let res = {
				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read =
					PoseidonReadChipset::<_, C, _, P, R>::new(Some(self.reader.as_slice()), loader);

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
		let mut poseidon_read =
			PoseidonRead::<_, G1Affine, Bn256_4_68, Params>::new(reader.as_slice(), NativeSVLoader);

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
				let loader = LoaderConfig::<C, _, P>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.main,
					config.poseidon_sponge.clone(),
				);

				let mut poseidon_read = PoseidonReadChipset::<_, C, _, P, R>::new(
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

		let mut poseidon_write = PoseidonWrite::<_, G1Affine, Bn256_4_68, Params>::init(Vec::new());

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
