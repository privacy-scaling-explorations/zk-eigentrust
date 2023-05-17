use super::{
	gen_pk,
	loader::{
		native::{NUM_BITS, NUM_LIMBS},
		Halo2LScalar, LoaderConfig,
	},
	transcript::{
		native::{PoseidonRead, PoseidonWrite, WIDTH},
		PoseidonReadChipset,
	},
};
use crate::{
	circuit::{FullRoundHasher, PartialRoundHasher},
	ecc::{
		EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig, EccUnreducedLadderConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		main::{MainChip, MainConfig},
	},
	integer::{
		native::Integer, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
		IntegerSubChip,
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
	rns::bn256::Bn256_4_68,
	Chip, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
	plonk::{create_proof, Circuit, ConstraintSystem, Error},
	poly::{
		commitment::ParamsProver,
		kzg::{
			commitment::{KZGCommitmentScheme, ParamsKZG},
			multiopen::ProverGWC,
		},
	},
	transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use rand::{thread_rng, RngCore};
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
		AccumulationScheme, AccumulationSchemeProver,
	},
	system::halo2::{compile, Config},
	verifier::{
		plonk::{PlonkProtocol, PlonkSuccinctVerifier},
		SnarkVerifier,
	},
};
use std::{rc::Rc, sync::Mutex};

type PSV = PlonkSuccinctVerifier<KzgAs<Bn256, Gwc19>>;
type SVK = KzgSuccinctVerifyingKey<G1Affine>;

#[derive(Clone)]
/// Snark structure
pub struct Snark {
	// Protocol
	protocol: PlonkProtocol<G1Affine>,
	// Instances
	instances: Vec<Vec<Fr>>,
	// Proof
	proof: Vec<u8>,
}

impl Snark {
	/// Create a new Snark
	fn new<C: Circuit<Fr>, R: RngCore>(
		params: &ParamsKZG<Bn256>, circuit: C, instances: Vec<Vec<Fr>>, rng: &mut R,
	) -> Self {
		let pk = gen_pk(params, &circuit);
		let config = Config::kzg().with_num_instance(vec![instances.len()]);

		let protocol = compile(params, pk.get_vk(), config);

		let instances_slice: Vec<&[Fr]> = instances.iter().map(|x| x.as_slice()).collect();
		let mut transcript = PoseidonWrite::<_, G1Affine, Bn256_4_68, Params>::new(Vec::new());
		create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
			params,
			&pk,
			&[circuit],
			&[instances_slice.as_slice()],
			rng,
			&mut transcript,
		)
		.unwrap();
		let proof = transcript.finalize();

		Self { protocol, instances, proof }
	}
}

#[derive(Clone)]
/// UnassignedSnark structure
pub struct UnassignedSnark {
	protocol: PlonkProtocol<G1Affine>,
	instances: Vec<Vec<Value<Fr>>>,
	proof: Option<Vec<u8>>,
}

impl From<Snark> for UnassignedSnark {
	fn from(snark: Snark) -> Self {
		Self {
			protocol: snark.protocol,
			instances: snark
				.instances
				.into_iter()
				.map(|instances| instances.into_iter().map(Value::known).collect_vec())
				.collect(),
			proof: Some(snark.proof),
		}
	}
}

impl UnassignedSnark {
	fn without_witnesses(&self) -> Self {
		UnassignedSnark {
			protocol: self.protocol.clone(),
			instances: self
				.instances
				.iter()
				.map(|instances| vec![Value::unknown(); instances.len()])
				.collect(),
			proof: None,
		}
	}

	fn proof(&self) -> Option<&[u8]> {
		self.proof.as_ref().map(Vec::as_slice)
	}
}

struct Aggregator {
	// Succinct Verifying Key
	svk: SVK,
	// Snarks for the aggregation
	snarks: Vec<UnassignedSnark>,
	// Instances
	instances: Vec<Fr>,
	// Accumulation Scheme Proof
	as_proof: Option<Vec<u8>>,
}

impl Clone for Aggregator {
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self {
			svk: self.svk.clone(),
			snarks: self.snarks.clone(),
			instances: self.instances.clone(),
			as_proof: self.as_proof.clone(),
		}
	}
}

impl Aggregator {
	/// Create a new aggregator.
	pub fn new(params: &ParamsKZG<Bn256>, snarks: Vec<Snark>) -> Self {
		let svk = params.get_g()[0].into();

		let mut plonk_proofs = Vec::new();
		for snark in &snarks {
			let mut transcript_read: PoseidonRead<_, G1Affine, Bn256_4_68, Params> =
				PoseidonRead::init(snark.proof.as_slice());
			let proof = PSV::read_proof(
				&svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = PSV::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap();
			plonk_proofs.extend(res);
		}

		let mut transcript_write =
			PoseidonWrite::<Vec<u8>, G1Affine, Bn256_4_68, Params>::new(Vec::new());
		let rng = &mut thread_rng();
		let accumulator = KzgAs::<Bn256, Gwc19>::create_proof(
			&Default::default(),
			&plonk_proofs,
			&mut transcript_write,
			rng,
		)
		.unwrap();
		let as_proof = transcript_write.finalize();

		let KzgAccumulator { lhs, rhs } = accumulator;
		let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, Bn256_4_68>::from_w(v).limbs)
			.concat();

		Self {
			svk,
			snarks: snarks.into_iter().map_into().collect(),
			instances,
			as_proof: Some(as_proof),
		}
	}
}

/// AggregatorConfig structure
#[derive(Clone)]
struct AggregatorConfig {
	// Configurations for the needed circuit configs.
	pub(crate) common: CommonConfig,
	pub(crate) main: MainConfig,
	pub(crate) poseidon_sponge: PoseidonSpongeConfig,
	pub(crate) ecc_mul_scalar: EccMulConfig,
}

impl AggregatorConfig {
	fn new(
		common: CommonConfig, main: MainConfig, poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
	) -> Self {
		Self { common, main, poseidon_sponge, ecc_mul_scalar }
	}
}

impl Circuit<Fr> for Aggregator {
	type Config = AggregatorConfig;
	type FloorPlanner = SimpleFloorPlanner;

	/// Returns a copy of this circuit with no witness values
	fn without_witnesses(&self) -> Self {
		Self {
			svk: self.svk,
			snarks: self.snarks.iter().map(UnassignedSnark::without_witnesses).collect(),
			instances: Vec::new(),
			as_proof: None,
		}
	}

	/// Configure the circuit.
	fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main_selector = MainChip::configure(&common, meta);
		let main = MainConfig::new(main_selector);

		let full_round_selector = FullRoundHasher::configure(&common, meta);
		let partial_round_selector = PartialRoundHasher::configure(&common, meta);
		let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

		let absorb_selector = AbsorbChip::<Fr, WIDTH>::configure(&common, meta);
		let poseidon_sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

		let bits2num = Bits2NumChip::configure(&common, meta);

		let int_red =
			IntegerReduceChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
		let int_add =
			IntegerAddChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
		let int_sub =
			IntegerSubChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
		let int_mul =
			IntegerMulChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);
		let int_div =
			IntegerDivChip::<Fq, Fr, NUM_LIMBS, NUM_BITS, Bn256_4_68>::configure(&common, meta);

		let ladder = EccUnreducedLadderConfig::new(int_add, int_sub, int_mul, int_div);
		let add = EccAddConfig::new(int_red, int_sub, int_mul, int_div);
		let double = EccDoubleConfig::new(int_red, int_add, int_sub, int_mul, int_div);
		let table_select = EccTableSelectConfig::new(main.clone());
		let ecc_mul_scalar = EccMulConfig::new(ladder, add, double, table_select, bits2num);

		AggregatorConfig { common, main, poseidon_sponge, ecc_mul_scalar }
	}

	/// Synthesize the circuit.
	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
	) -> Result<(), Error> {
		let layouter_rc = Rc::new(Mutex::new(layouter.namespace(|| "loader")));
		let loader_config = LoaderConfig::<G1Affine, _, Bn256_4_68>::new(
			layouter_rc.clone(),
			config.common.clone(),
			config.ecc_mul_scalar,
			config.main,
			config.poseidon_sponge,
		);
		let mut plonk_proofs = Vec::new();
		for snark in &self.snarks {
			let protocol = snark.protocol.loaded(&loader_config);
			let mut transcript_read: PoseidonReadChipset<&[u8], G1Affine, _, Bn256_4_68, Params> =
				PoseidonReadChipset::new(snark.proof(), loader_config.clone());

			let mut instances: Vec<Vec<Halo2LScalar<G1Affine, _, Bn256_4_68>>> = Vec::new();
			let instance_flatten =
				snark.instances.clone().into_iter().flatten().collect::<Vec<Value<Fr>>>();
			let mut instance_collector: Vec<Option<Halo2LScalar<G1Affine, _, Bn256_4_68>>> =
				vec![None; instance_flatten.len()];

			{
				let mut lb = layouter_rc.lock().unwrap();
				lb.assign_region(
					|| "assign_instances",
					|region: Region<'_, Fr>| {
						let mut ctx = RegionCtx::new(region, 0);

						let mut id = 0;
						while id < instance_flatten.len() {
							let value = ctx.assign_advice(
								config.common.advice[id % ADVICE],
								instance_flatten[id],
							)?;
							let lscalar = Halo2LScalar::new(value, loader_config.clone());
							instance_collector[id] = Some(lscalar.clone());

							id += 1;
							if 0 < id && id % ADVICE == 0 {
								ctx.next();
							}
						}
						Ok(())
					},
				)?;
				// // Drop the layouter reference
				// drop(lb);
			}

			let mut id = 0;
			for i in 0..snark.instances.len() {
				let mut temp: Vec<Halo2LScalar<G1Affine, _, Bn256_4_68>> = Vec::new();
				for _ in 0..snark.instances[i].len() {
					temp.push(instance_collector[id].clone().unwrap());
					id += 1;
				}
				instances.push(temp);
			}

			let proof = PlonkSuccinctVerifier::<KzgAs<Bn256, Gwc19>>::read_proof(
				&self.svk, &protocol, &instances, &mut transcript_read,
			)
			.unwrap();

			let res = PlonkSuccinctVerifier::<KzgAs<Bn256, Gwc19>>::verify(
				&self.svk, &protocol, &instances, &proof,
			)
			.unwrap();
			plonk_proofs.extend(res);
		}

		let as_proof = self.as_proof.as_ref().map(Vec::as_slice);
		let mut transcript: PoseidonReadChipset<&[u8], G1Affine, _, Bn256_4_68, Params> =
			PoseidonReadChipset::new(as_proof, loader_config);
		let proof =
			KzgAs::<Bn256, Gwc19>::read_proof(&Default::default(), &plonk_proofs, &mut transcript)
				.unwrap();

		let accumulator =
			KzgAs::<Bn256, Gwc19>::verify(&Default::default(), &plonk_proofs, &proof).unwrap();

		let lhs_x = accumulator.lhs.inner.x;
		let lhs_y = accumulator.lhs.inner.y;

		let rhs_x = accumulator.rhs.inner.x;
		let rhs_y = accumulator.rhs.inner.y;

		{
			let mut row = 0;
			let mut lb = layouter_rc.lock().unwrap();
			for limb in lhs_x.limbs {
				lb.constrain_instance(limb.cell(), config.common.instance, row)?;
				row += 1;
			}
			for limb in lhs_y.limbs {
				lb.constrain_instance(limb.cell(), config.common.instance, row)?;
				row += 1;
			}
			for limb in rhs_x.limbs {
				lb.constrain_instance(limb.cell(), config.common.instance, row)?;
				row += 1;
			}
			for limb in rhs_y.limbs {
				lb.constrain_instance(limb.cell(), config.common.instance, row)?;
				row += 1;
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod test {

	use crate::{
		circuit::{FullRoundHasher, PartialRoundHasher},
		ecc::{
			EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
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
		poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
		rns::bn256::Bn256_4_68,
		utils::generate_params,
		verifier::{
			loader::native::{NUM_BITS, NUM_LIMBS},
			transcript::native::WIDTH,
		},
		Chip, CommonConfig, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fq, Fr},
		plonk::{Circuit, ConstraintSystem, Error},
		poly::Rotation,
	};
	use rand::thread_rng;

	use super::{Aggregator, AggregatorConfig, Snark};

	type P = Bn256_4_68;
	type Scalar = Fr;
	type Base = Fq;
	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
		poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		aggregator: Aggregator,
	}

	impl TestCircuit {
		fn new(aggregator: Aggregator) -> Self {
			Self { aggregator }
		}
	}

	impl Circuit<Scalar> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
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

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let aggregator_config = AggregatorConfig::new(
				config.common, config.main, config.poseidon_sponge, config.ecc_mul_scalar,
			);

			self.aggregator.synthesize(aggregator_config, layouter.namespace(|| "aggregate"))?;

			Ok(())
		}
	}

	#[derive(Clone)]
	pub struct MulConfig {
		common: CommonConfig,
	}

	/// Constructs individual cells for the configuration elements.
	#[derive(Debug, Clone)]
	pub struct MulChip<Scalar> {
		x: Scalar,
		y: Scalar,
	}

	impl MulChip<Scalar> {
		/// Create a new chip.
		pub fn new(x: Scalar, y: Scalar) -> Self {
			MulChip { x, y }
		}
	}

	impl Circuit<Scalar> for MulChip<Scalar> {
		type Config = MulConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
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
					let assigned_x =
						ctx.assign_advice(config.common.advice[0], Value::known(self.x))?;
					let assigned_y =
						ctx.assign_advice(config.common.advice[1], Value::known(self.y))?;

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

	// #[ignore = "Aggregator fails"]
	#[test]
	fn test_aggregator() {
		use std::time::Instant;
		let start = Instant::now();
		// Testing Aggregator
		let rng = &mut thread_rng();
		let k = 21;
		let params = generate_params::<Bn256>(k);
		let end = start.elapsed();
		println!("Generate params: {:?}", end);

		let random_circuit_1 = MulChip::new(Fr::one(), Fr::one());
		let random_circuit_2 = MulChip::new(Fr::one(), Fr::one());

		let instances_1: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
		let instances_2: Vec<Vec<Fr>> = vec![vec![Fr::one()]];

		let snark_1 = Snark::new(&params.clone(), random_circuit_1, instances_1, rng);
		println!("snark_1: {:?}", start.elapsed());
		let snark_2 = Snark::new(&params.clone(), random_circuit_2, instances_2, rng);
		println!("snark_2: {:?}", start.elapsed());

		let snarks = vec![snark_1, snark_2];
		let aggregator = Aggregator::new(&params, snarks.clone());

		let circuit = TestCircuit::new(aggregator.clone());
		let prover = MockProver::run(k, &circuit, vec![aggregator.instances]).unwrap();
		println!("Total time: {:?}", start.elapsed());

		assert_eq!(prover.verify(), Ok(()));
	}
}
