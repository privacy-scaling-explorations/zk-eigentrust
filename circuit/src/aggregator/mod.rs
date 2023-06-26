use self::native::Snark;

/// Native version of Aggregator
pub mod native;
use crate::{
	circuit::{FullRoundHasher, PartialRoundHasher},
	ecc::same_curve::{
		EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig, EccUnreducedLadderConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		main::{MainChip, MainConfig},
	},
	integer::{IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip, IntegerSubChip},
	params::rns::bn256::Bn256_4_68,
	params::{ecc::bn254::Bn254Params, hasher::poseidon_bn254_5x5::Params},
	poseidon::{
		sponge::{PoseidonSpongeConfig, StatefulSpongeChipset},
		PoseidonConfig,
	},
	verifier::{
		loader::{
			native::{NUM_BITS, NUM_LIMBS},
			Halo2LScalar, LoaderConfig,
		},
		transcript::{native::WIDTH, TranscriptReadChipset},
	},
	Chip, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
	plonk::{Circuit, ConstraintSystem, Error},
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

/// Plonk verifier
pub type Psv = PlonkSuccinctVerifier<KzgAs<Bn256, Gwc19>>;
/// KZG succinct verifying key
pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;

#[derive(Debug, Clone)]
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
	fn without_witness(&self) -> Self {
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
		self.proof.as_deref()
	}
}

struct Aggregator {
	// Succinct Verifying Key
	svk: Svk,
	// Snarks for the aggregation
	snarks: Vec<UnassignedSnark>,
	// Accumulation Scheme Proof
	as_proof: Option<Vec<u8>>,
}

impl Aggregator {
	/// Create a new aggregator.
	pub fn new(svk: Svk, snarks: Vec<Snark>, as_proof: Vec<u8>) -> Self {
		Self { svk, snarks: snarks.into_iter().map_into().collect(), as_proof: Some(as_proof) }
	}
}

impl Clone for Aggregator {
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self { svk: self.svk, snarks: self.snarks.clone(), as_proof: self.as_proof.clone() }
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
			snarks: self.snarks.iter().map(UnassignedSnark::without_witness).collect(),
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
		let poseidon_sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

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
		let assigned_instances = layouter.assign_region(
			|| "assign_instances",
			|region: Region<'_, Fr>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut advice_i = 0;
				let mut assigned_instances = Vec::new();
				for snark in &self.snarks {
					let mut instances_collector = Vec::new();
					for inst_vec in &snark.instances {
						let mut inst_vec_collector = Vec::new();
						for inst in inst_vec {
							let value = ctx.assign_advice(config.common.advice[advice_i], *inst)?;
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

		let _accumulator_limbs = {
			let loader_config = LoaderConfig::<
				'_,
				G1Affine,
				_,
				Bn256_4_68,
				StatefulSpongeChipset<Fr, WIDTH, Params>,
				Bn254Params,
			>::new(
				layouter.namespace(|| "loader"),
				config.common.clone(),
				config.ecc_mul_scalar,
				config.main,
				config.poseidon_sponge,
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

				let mut transcript_read: TranscriptReadChipset<
					&[u8],
					G1Affine,
					_,
					Bn256_4_68,
					StatefulSpongeChipset<Fr, WIDTH, Params>,
					Bn254Params,
				> = TranscriptReadChipset::new(snark.proof(), loader_config.clone());

				let proof = Psv::read_proof(
					&self.svk, &protocol, &loaded_instances, &mut transcript_read,
				)
				.unwrap();
				let res = Psv::verify(&self.svk, &protocol, &loaded_instances, &proof).unwrap();

				accumulators.extend(res);
			}

			let as_proof = self.as_proof.as_deref();
			let mut transcript: TranscriptReadChipset<
				&[u8],
				G1Affine,
				_,
				Bn256_4_68,
				StatefulSpongeChipset<Fr, WIDTH, Params>,
				Bn254Params,
			> = TranscriptReadChipset::new(as_proof, loader_config);
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

			[lhs_x, lhs_y, rhs_x, rhs_y].map(|v| v.limbs).into_iter().flatten()
		};

		// TODO: Uncomment when the bug is fixed
		// for (row, inst) in accumulator_limbs.enumerate() {
		// 	layouter.constrain_instance(inst.cell(), config.common.instance, row)?;
		// }

		Ok(())
	}
}

#[cfg(test)]
mod test {

	use super::{Aggregator, Snark};
	use crate::{
		aggregator::native::NativeAggregator, utils::generate_params, CommonConfig, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem, Error},
		poly::Rotation,
	};
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
		let aggregator = Aggregator::new(svk, snarks, as_proof);

		let prover = MockProver::run(k, &aggregator, vec![instances]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}
}
