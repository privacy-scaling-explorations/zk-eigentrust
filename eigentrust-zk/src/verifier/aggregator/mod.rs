/// Native version of Aggregator
pub mod native;
use self::native::Snark;
use super::loader::native::{NUM_BITS, NUM_LIMBS};
use crate::{
	ecc::{AuxConfig, EccAddConfig, EccMulConfig},
	gadgets::main::MainConfig,
	params::{ecc::EccParams, rns::RnsParams},
	verifier::{
		loader::{Halo2LScalar, LoaderConfig},
		transcript::TranscriptReadChipset,
	},
	Chipset, CommonConfig, FieldExt, RegionCtx, SpongeHasher, SpongeHasherChipset, ADVICE,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::{
		bn256::{Bn256, G1Affine},
		pairing::MultiMillerLoop,
		CurveAffine,
	},
	plonk::Error,
};
use itertools::Itertools;
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAs, KzgSuccinctVerifyingKey},
		AccumulationScheme,
	},
	verifier::{
		plonk::{PlonkProtocol, PlonkSuccinctVerifier},
		SnarkVerifier,
	},
};
use std::marker::PhantomData;

/// Plonk verifier
pub type Psv = PlonkSuccinctVerifier<KzgAs<Bn256, Gwc19>>;
/// KZG succinct verifying key
pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;

#[derive(Debug, Clone)]
/// UnassignedSnark structure
pub struct UnassignedSnark<C: CurveAffine, P, const WIDTH: usize, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	protocol: PlonkProtocol<C>,
	instances: Vec<Vec<Value<C::Scalar>>>,
	proof: Option<Vec<u8>>,
	_p: PhantomData<(P, S, EC, E)>,
}

impl<C: CurveAffine, P, const WIDTH: usize, S, SN, EC, E> From<Snark<C, P, WIDTH, SN, EC, E>>
	for UnassignedSnark<C, P, WIDTH, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	SN: SpongeHasher<C::Scalar>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	fn from(snark: Snark<C, P, WIDTH, SN, EC, E>) -> Self {
		Self {
			protocol: snark.protocol,
			instances: snark
				.instances
				.into_iter()
				.map(|instances| instances.into_iter().map(Value::known).collect_vec())
				.collect(),
			proof: Some(snark.proof),
			_p: PhantomData,
		}
	}
}

impl<C: CurveAffine, P, const WIDTH: usize, S, EC, E> UnassignedSnark<C, P, WIDTH, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	fn without_witness(&self) -> Self {
		UnassignedSnark {
			protocol: self.protocol.clone(),
			instances: self
				.instances
				.iter()
				.map(|instances| vec![Value::unknown(); instances.len()])
				.collect(),
			proof: None,
			_p: PhantomData,
		}
	}

	fn proof(&self) -> Option<&[u8]> {
		self.proof.as_deref()
	}
}

#[derive(Debug)]
/// AggregatorChipset
pub struct AggregatorChipset<C: CurveAffine, P, const WIDTH: usize, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Succinct Verifying Key
	svk: Svk,
	// Snarks for the aggregation
	snarks: Vec<UnassignedSnark<C, P, WIDTH, S, EC, E>>,
	// Accumulation Scheme Proof
	as_proof: Option<Vec<u8>>,
	// Phantom Data
	_p: PhantomData<(P, S, EC, E)>,
}

impl<C: CurveAffine, P, const WIDTH: usize, S, EC, E> AggregatorChipset<C, P, WIDTH, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Create a new aggregator.
	pub fn new(
		svk: Svk, snarks: Vec<UnassignedSnark<C, P, WIDTH, S, EC, E>>, as_proof: Option<Vec<u8>>,
	) -> Self {
		Self { svk, snarks, as_proof, _p: PhantomData }
	}
}

impl<C: CurveAffine, P, const WIDTH: usize, S, EC, E> Clone
	for AggregatorChipset<C, P, WIDTH, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self {
			svk: self.svk,
			snarks: self.snarks.clone(),
			as_proof: self.as_proof.clone(),
			_p: PhantomData,
		}
	}
}

/// AggregatorConfig structure
#[derive(Clone)]
pub struct AggregatorConfig<F: FieldExt, S, const WIDTH: usize>
where
	S: SpongeHasherChipset<F, WIDTH>,
{
	// Configurations for the needed circuit configs.
	pub(crate) main: MainConfig,
	pub(crate) sponge: S::Config,
	pub(crate) ecc_mul_scalar: EccMulConfig,
	pub(crate) ecc_add: EccAddConfig,
	pub(crate) aux: AuxConfig,
}

impl<F: FieldExt, S, const WIDTH: usize> AggregatorConfig<F, S, WIDTH>
where
	S: SpongeHasherChipset<F, WIDTH>,
{
	fn new(
		main: MainConfig, sponge: S::Config, ecc_mul_scalar: EccMulConfig, ecc_add: EccAddConfig,
		aux: AuxConfig,
	) -> Self {
		Self { main, sponge, ecc_mul_scalar, ecc_add, aux }
	}
}

impl<C: CurveAffine, P, const WIDTH: usize, S, EC, E> Chipset<C::Scalar>
	for AggregatorChipset<C, P, WIDTH, S, EC, E>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<C::Scalar, WIDTH>,
	EC: EccParams<C>,
	E: MultiMillerLoop,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = AggregatorConfig<C::ScalarExt, S, WIDTH>;
	type Output = Vec<AssignedCell<C::Scalar, C::Scalar>>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<C::Scalar>,
	) -> Result<Self::Output, Error> {
		let assigned_instances = layouter.assign_region(
			|| "assign_instances",
			|region: Region<'_, C::Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut advice_i = 0;
				let mut assigned_instances = Vec::new();
				for snark in &self.snarks {
					let mut instances_collector = Vec::new();
					for inst_vec in &snark.instances {
						let mut inst_vec_collector = Vec::new();
						for inst in inst_vec {
							let value = ctx.assign_advice(common.advice[advice_i], *inst)?;
							inst_vec_collector.push(value);

							advice_i += 1;
							if advice_i % ADVICE == 0 {
								advice_i = 0;
								ctx.next();
							}
						}
						instances_collector.push(inst_vec_collector);
					}
					assigned_instances.push(instances_collector);
				}
				Ok(assigned_instances)
			},
		)?;

		let accumulator_limbs = {
			let loader_config = LoaderConfig::<'_, C, _, P, WIDTH, S, EC>::new(
				layouter.namespace(|| "loader"),
				common.clone(),
				config.ecc_mul_scalar.clone(),
				config.ecc_add.clone(),
				config.aux.clone(),
				config.main.clone(),
				config.sponge.clone(),
			);

			let mut accumulators = Vec::new();
			for (i, snark) in self.snarks.iter().enumerate() {
				let mut loaded_instances = Vec::new();
				for inst_vec in &assigned_instances[i] {
					let mut loaded_inst_vec = Vec::new();
					for inst in inst_vec {
						let loaded_instance =
							Halo2LScalar::new(inst.clone(), loader_config.clone());
						loaded_inst_vec.push(loaded_instance);
					}
					loaded_instances.push(loaded_inst_vec);
				}

				let protocol = snark.protocol.loaded(&loader_config);

				let mut transcript_read: TranscriptReadChipset<&[u8], C, _, P, WIDTH, S, EC> =
					TranscriptReadChipset::new(snark.proof(), loader_config.clone());

				let proof = PlonkSuccinctVerifier::<KzgAs<E, Gwc19>>::read_proof(
					&self.svk, &protocol, &loaded_instances, &mut transcript_read,
				)
				.unwrap();
				let res = PlonkSuccinctVerifier::<KzgAs<E, Gwc19>>::verify(
					&self.svk, &protocol, &loaded_instances, &proof,
				)
				.unwrap();

				accumulators.extend(res);
			}

			let as_proof = self.as_proof.as_deref();
			let mut transcript: TranscriptReadChipset<&[u8], C, _, P, WIDTH, S, EC> =
				TranscriptReadChipset::new(as_proof, loader_config);
			let proof = KzgAs::<Bn256, Gwc19>::read_proof(
				&Default::default(),
				&accumulators,
				&mut transcript,
			)
			.unwrap();

			let accumulator =
				KzgAs::<Bn256, Gwc19>::verify(&Default::default(), &accumulators, &proof).unwrap();

			let lhs_x = accumulator.lhs.inner.x;
			let lhs_y = accumulator.lhs.inner.y;

			let rhs_x = accumulator.rhs.inner.x;
			let rhs_y = accumulator.rhs.inner.y;

			[lhs_x, lhs_y, rhs_x, rhs_y].map(|v| v.limbs).into_iter().flatten().collect_vec()
		};

		Ok(accumulator_limbs)
	}
}

#[cfg(test)]
mod test {
	use super::{
		native::NativeAggregator, AggregatorChipset, AggregatorConfig, Snark, Svk, UnassignedSnark,
	};
	use crate::{
		circuits::{FullRoundHasher, PartialRoundHasher, HASHER_WIDTH},
		ecc::{
			AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
			EccUnreducedLadderConfig,
		},
		gadgets::{
			absorb::AbsorbChip,
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip, IntegerSubChip,
		},
		params::{hasher::poseidon_bn254_5x5::Params, rns::bn256::Bn256_4_68},
		poseidon::{
			sponge::{PoseidonSpongeConfig, StatefulSpongeChipset},
			PoseidonConfig,
		},
		utils::generate_params,
		verifier::{
			loader::native::{NUM_BITS, NUM_LIMBS},
			transcript::native::WIDTH,
		},
		Chip, Chipset, CommonConfig, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
		plonk::{Circuit, ConstraintSystem, Error},
		poly::Rotation,
	};
	use itertools::Itertools;
	use rand::thread_rng;

	type Scalar = Fr;

	#[derive(Clone)]
	pub struct MulConfig {
		common: CommonConfig,
	}

	/// Constructs individual cells for the configuration elements.
	#[derive(Debug, Clone)]
	pub struct MulChip<Scalar> {
		x: Value<Scalar>,
		y: Value<Scalar>,
	}

	impl MulChip<Scalar> {
		/// Create a new chip.
		pub fn new(x: Scalar, y: Scalar) -> Self {
			MulChip { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Scalar> for MulChip<Scalar> {
		type Config = MulConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		/// Make the circuit config.
		fn configure(meta: &mut ConstraintSystem<Scalar>) -> MulConfig {
			let common = CommonConfig::new(meta);
			let s = meta.selector();

			meta.create_gate("mul", |v_cells| {
				let x_exp = v_cells.query_advice(common.advice[0], Rotation::cur());
				let y_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
				let x_next_exp = v_cells.query_advice(common.advice[0], Rotation::next());
				let s_exp = v_cells.query_selector(s);

				vec![s_exp * ((x_exp * y_exp) - x_next_exp)]
			});

			MulConfig { common }
		}

		/// Synthesize the circuit.
		fn synthesize(
			&self, config: MulConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let result = layouter.assign_region(
				|| "assign",
				|region: Region<'_, Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let assigned_x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let assigned_y = ctx.assign_advice(config.common.advice[1], self.y)?;
					let out = assigned_x.value().cloned() * assigned_y.value();
					ctx.next();
					let res = ctx.assign_advice(config.common.advice[0], out)?;

					Ok(res)
				},
			)?;
			layouter.constrain_instance(result.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[derive(Clone)]
	struct AggregatorTestCircuitConfig {
		common: CommonConfig,
		aggregator: AggregatorConfig<Fr, StatefulSpongeChipset<Fr, HASHER_WIDTH, Params>, 5>,
	}

	#[derive(Clone)]
	struct AggregatorTestCircuit {
		svk: Svk,
		snarks: Vec<UnassignedSnark<G1Affine>>,
		as_proof: Option<Vec<u8>>,
	}

	impl AggregatorTestCircuit {
		fn new(svk: Svk, snarks: Vec<Snark>, as_proof: Vec<u8>) -> Self {
			Self { svk, snarks: snarks.into_iter().map_into().collect(), as_proof: Some(as_proof) }
		}
	}

	impl Circuit<Fr> for AggregatorTestCircuit {
		type Config = AggregatorTestCircuitConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				svk: self.svk,
				snarks: self.snarks.iter().map(UnassignedSnark::without_witness).collect(),
				as_proof: None,
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);

			let full_round_selector = FullRoundHasher::configure(&common, meta);
			let partial_round_selector = PartialRoundHasher::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let absorb_selector = AbsorbChip::<Fr, WIDTH>::configure(&common, meta);
			let sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			let bits2num = Bits2NumChip::configure(&common, meta);

			let int_red = IntegerReduceChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(
				&common, meta,
			);
			let int_add =
				IntegerAddChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
			let int_sub =
				IntegerSubChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
			let int_mul =
				IntegerMulChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
			let int_div =
				IntegerDivChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);

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

			let aggregator = AggregatorConfig { main, sponge, ecc_mul_scalar, ecc_add, aux };

			AggregatorTestCircuitConfig { common, aggregator }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let aggregator_chipset =
				AggregatorChipset::new(self.svk, self.snarks.clone(), self.as_proof.clone());
			let accumulator_limbs = aggregator_chipset.synthesize(
				&config.common,
				&config.aggregator,
				layouter.namespace(|| "aggregator chipset"),
			)?;

			for (row, inst) in accumulator_limbs.iter().enumerate() {
				layouter.constrain_instance(inst.cell(), config.common.instance, row)?;
			}
			Ok(())
		}
	}

	#[ignore = "Aggregator takes too long to run"]
	#[test]
	fn test_aggregator() {
		// Testing Aggregator
		let rng = &mut thread_rng();
		let k = 22;
		let params = generate_params::<Bn256>(k);

		let random_circuit_1 = MulChip::new(Fr::one(), Fr::one());
		let random_circuit_2 = MulChip::new(Fr::one(), Fr::one());

		let instances_1: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
		let instances_2: Vec<Vec<Fr>> = vec![vec![Fr::one()]];

		let snark_1 = Snark::new(&params, random_circuit_1, instances_1, rng);
		let snark_2 = Snark::new(&params, random_circuit_2, instances_2, rng);

		let snarks = vec![snark_1, snark_2];
		let NativeAggregator { svk, snarks, instances, as_proof } =
			NativeAggregator::new(&params, snarks);

		let aggregator_circuit = AggregatorTestCircuit::new(svk, snarks, as_proof);
		let prover = MockProver::run(k, &aggregator_circuit, vec![instances]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}
}
