/// Native version of Aggregator
pub mod native;

use self::native::Snark;
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
	halo2curves::CurveAffine,
	plonk::Error,
};
use itertools::Itertools;
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAs, KzgSuccinctVerifyingKey},
		AccumulationScheme,
	},
	util::arithmetic::MultiMillerLoop,
	verifier::{
		plonk::{PlonkProtocol, PlonkSuccinctVerifier},
		SnarkVerifier,
	},
};
use std::marker::PhantomData;

/// Plonk verifier
pub type Psv<E> = PlonkSuccinctVerifier<KzgAs<E, Gwc19>>;
/// KZG succinct verifying key
pub type Svk<C> = KzgSuccinctVerifyingKey<C>;

#[derive(Debug, Clone)]
/// UnassignedSnark structure
pub struct UnassignedSnark<E>
where
	E: MultiMillerLoop,
	E::Scalar: FieldExt,
{
	protocol: PlonkProtocol<E::G1Affine>,
	instances: (Vec<Vec<E::Scalar>>, Vec<Vec<Value<E::Scalar>>>),
	proof: Option<Vec<u8>>,
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, EC>
	From<Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>> for UnassignedSnark<E>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
{
	fn from(snark: Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>) -> Self {
		Self {
			protocol: snark.protocol,
			instances: (
				snark.instances.clone(), 
				snark
				.instances
				.into_iter()
				.map(|instances| instances.into_iter().map(Value::known).collect_vec())
				.collect()
			),
			proof: Some(snark.proof),
		}
	}
}

impl<E> UnassignedSnark<E>
where
	E: MultiMillerLoop,
	E::Scalar: FieldExt,
{
	/// Returns the struct with unknown witnesses
	pub fn without_witness(&self) -> Self {
		UnassignedSnark {
			protocol: self.protocol.clone(),
			instances: self.instances.clone(),
			proof: None,
		}
	}

	fn proof(&self) -> Option<&[u8]> {
		self.proof.as_deref()
	}
}

#[derive(Debug)]
/// AggregatorChipset
pub struct AggregatorChipset<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, H, EC>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
{
	// Succinct Verifying Key
	svk: Svk<E::G1Affine>,
	// Snarks for the aggregation
	snarks: Vec<UnassignedSnark<E>>,
	// Accumulation Scheme Proof
	as_proof: Option<Vec<u8>>,
	// Phantom Data
	_p: PhantomData<(P, S, H, EC, E)>,
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, H, EC>
	AggregatorChipset<E, NUM_LIMBS, NUM_BITS, P, S, H, EC>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
{
	/// Create a new aggregator.
	pub fn new(
		svk: Svk<E::G1Affine>, snarks: Vec<UnassignedSnark<E>>, as_proof: Option<Vec<u8>>,
	) -> Self {
		Self { svk, snarks, as_proof, _p: PhantomData }
	}
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, H, EC> Clone
	for AggregatorChipset<E, NUM_LIMBS, NUM_BITS, P, S, H, EC>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
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
#[derive(Clone, Debug)]
pub struct AggregatorConfig<F: FieldExt, S>
where
	S: SpongeHasherChipset<F>,
{
	// Configurations for the needed circuit configs.
	pub(crate) main: MainConfig,
	pub(crate) sponge: S::Config,
	pub(crate) ecc_mul_scalar: EccMulConfig,
	pub(crate) ecc_add: EccAddConfig,
	pub(crate) aux: AuxConfig,
}

impl<F: FieldExt, S> AggregatorConfig<F, S>
where
	S: SpongeHasherChipset<F>,
{
	/// Constructs new AggregatorConfig
	pub fn new(
		main: MainConfig, sponge: S::Config, ecc_mul_scalar: EccMulConfig, ecc_add: EccAddConfig,
		aux: AuxConfig,
	) -> Self {
		Self { main, sponge, ecc_mul_scalar, ecc_add, aux }
	}
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, H, EC> Chipset<E::Scalar>
	for AggregatorChipset<E, NUM_LIMBS, NUM_BITS, P, S, H, EC>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
{
	type Config = AggregatorConfig<E::Scalar, S>;
	type Output = Vec<AssignedCell<E::Scalar, E::Scalar>>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<E::Scalar>,
	) -> Result<Self::Output, Error> {
		let assigned_instances = layouter.assign_region(
			|| "assign_instances",
			|region: Region<'_, E::Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut advice_i = 0;
				let mut assigned_instances = Vec::new();
				for snark in &self.snarks {
					let mut instances_collector = Vec::new();
					for inst_vec in &snark.instances.1 {
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
			let loader_config =
				LoaderConfig::<'_, E::G1Affine, _, NUM_LIMBS, NUM_BITS, P, S, EC>::new(
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
				for (j, inst_vec) in assigned_instances[i].iter().enumerate() {
					let mut loaded_inst_vec = Vec::new();
					for (k, inst) in inst_vec.iter().enumerate() {
						let loaded_instance =
							Halo2LScalar::new((snark.instances.0[j][k].clone(), inst.clone()), loader_config.clone());
						loaded_inst_vec.push(loaded_instance);
					}
					loaded_instances.push(loaded_inst_vec);
				}

				let protocol = snark.protocol.loaded(&loader_config);

				let mut transcript_read: TranscriptReadChipset<
					&[u8],
					E::G1Affine,
					_,
					NUM_LIMBS,
					NUM_BITS,
					P,
					S,
					H,
					EC,
				> = TranscriptReadChipset::new(snark.proof(), loader_config.clone());

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
			let mut transcript: TranscriptReadChipset<
				&[u8],
				E::G1Affine,
				_,
				NUM_LIMBS,
				NUM_BITS,
				P,
				S,
				H,
				EC,
			> = TranscriptReadChipset::new(as_proof, loader_config);
			let proof =
				KzgAs::<E, Gwc19>::read_proof(&Default::default(), &accumulators, &mut transcript)
					.unwrap();

			let accumulator =
				KzgAs::<E, Gwc19>::verify(&Default::default(), &accumulators, &proof).unwrap();

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
		circuits::{
			dynamic_sets::native::Attestation, ECDSAKeypair, ECDSAPublicKey, EigenTrust4,
			FullRoundHasher, NativeEigenTrust4, Opinion4, PartialRoundHasher, PoseidonNativeHasher,
			PoseidonNativeSponge, SignedAttestationSecp, SpongeHasher, HASHER_WIDTH,
		},
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
		params::{ecc::bn254::Bn254Params, rns::bn256::Bn256_4_68},
		poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
		utils::{big_to_fe, fe_to_big, generate_params, prove_and_verify},
		verifier::transcript::native::WIDTH,
		Chip, Chipset, CommonConfig, RegionCtx,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fq, Fr, G1Affine},
			ff::PrimeField,
		},
		plonk::{Circuit, ConstraintSystem, Error},
		poly::Rotation,
	};
	use itertools::Itertools;
	use rand::thread_rng;

	type E = Bn256;
	type C = G1Affine;
	type Scalar = Fr;
	type W = Fq;
	type P = Bn256_4_68;
	type EC = Bn254Params;
	type S = PoseidonNativeSponge;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const DOMAIN: u128,
	>(
		keypair: &ECDSAKeypair, pks: &[Scalar], scores: &[Scalar],
	) -> Vec<Option<SignedAttestationSecp>> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);
		let rng = &mut thread_rng();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i] == Scalar::ZERO {
				res.push(None)
			} else {
				let (about, key, value, message) =
					(pks[i], Scalar::from_u128(DOMAIN), scores[i], Scalar::zero());
				let attestation = Attestation::new(about, key, value, message);
				let msg = big_to_fe(fe_to_big(
					attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>(),
				));
				let signature = keypair.sign(msg, rng);
				let signed_attestation = SignedAttestationSecp::new(attestation, signature);

				res.push(Some(signed_attestation));
			}
		}
		res
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const DOMAIN: u128,
	>(
		ops: Vec<Vec<Scalar>>,
	) -> (
		Vec<Vec<Option<SignedAttestationSecp>>>,
		Vec<Option<ECDSAPublicKey>>,
		Vec<Fr>,
	) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let domain = Scalar::from_u128(DOMAIN);
		let mut set = NativeEigenTrust4::new(domain);

		let rng = &mut thread_rng();

		let keypairs: Vec<ECDSAKeypair> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| ECDSAKeypair::generate_keypair(rng)).collect();
		let pks: Vec<ECDSAPublicKey> = keypairs.iter().map(|kp| kp.public_key.clone()).collect();
		let pks_fr: Vec<Scalar> = keypairs.iter().map(|kp| kp.public_key.to_address()).collect();

		// Add the "address"(pk_fr) to the set
		pks_fr.iter().for_each(|pk| set.add_member(*pk));

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();
			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, DOMAIN>(
				&keypairs[i], &pks_fr, &scores,
			);
			set.update_op(pks[i].clone(), op_i);
		}

		let s = set.converge();

		// Prepare the EigenTrustSet Circuit inputs
		let (attestations, set, op_hash) = {
			let mut attestations = Vec::new();
			let mut set = Vec::new();

			for i in 0..NUM_NEIGHBOURS {
				let addr = pks[i].to_address();
				set.push(addr);
			}

			let mut op_hashes = Vec::new();
			for i in 0..NUM_NEIGHBOURS {
				let mut attestations_i = Vec::new();

				// Attestation to the other peers
				for j in 0..NUM_NEIGHBOURS {
					let attestation =
						Attestation::new(pks[j].to_address(), domain, ops[i][j], Scalar::ZERO);

					let att_hash = attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>();
					let att_hash = big_to_fe(fe_to_big(att_hash));

					let signature = keypairs[i].sign(att_hash, rng);
					let signed_att = SignedAttestationSecp::new(attestation, signature);

					attestations_i.push(signed_att);
				}
				attestations.push(attestations_i);

				let op = Opinion4::new(pks[i].clone(), attestations[i].clone(), domain);
				let (_, _, op_hash) = op.validate(set.clone());
				op_hashes.push(op_hash);
			}
			let mut sponge = PoseidonNativeSponge::new();
			sponge.update(&op_hashes);
			let op_hash = sponge.squeeze();

			(attestations, set, op_hash)
		};

		let mut opt_att = Vec::new();
		let mut opt_pks = Vec::new();

		for i in 0..NUM_NEIGHBOURS {
			let mut att_row = Vec::new();
			for j in 0..NUM_NEIGHBOURS {
				att_row.push(Some(attestations[i][j].clone()));
			}
			opt_att.push(att_row);
			opt_pks.push(Some(pks[i].clone()));
		}

		// Constructing public inputs for the circuit
		let mut public_inputs = set.clone();
		public_inputs.extend(s.clone());
		public_inputs.push(domain);
		public_inputs.push(op_hash);

		(opt_att, opt_pks, public_inputs)
	}

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
		aggregator: AggregatorConfig<Scalar, SpongeHasher>,
	}

	#[derive(Clone)]
	struct AggregatorTestCircuit {
		svk: Svk<C>,
		snarks: Vec<UnassignedSnark<E>>,
		as_proof: Option<Vec<u8>>,
	}

	impl AggregatorTestCircuit {
		fn new(
			svk: Svk<C>, snarks: Vec<Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>>, as_proof: Vec<u8>,
		) -> Self {
			Self { svk, snarks: snarks.into_iter().map_into().collect(), as_proof: Some(as_proof) }
		}
	}

	impl Circuit<Scalar> for AggregatorTestCircuit {
		type Config = AggregatorTestCircuitConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				svk: self.svk,
				snarks: self.snarks.iter().map(UnassignedSnark::without_witness).collect(),
				as_proof: None,
			}
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);

			let full_round_selector = FullRoundHasher::configure(&common, meta);
			let partial_round_selector = PartialRoundHasher::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let absorb_selector = AbsorbChip::<Scalar, WIDTH>::configure(&common, meta);
			let sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			let bits2num = Bits2NumChip::configure(&common, meta);

			let int_red =
				IntegerReduceChip::<W, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_add =
				IntegerAddChip::<W, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_sub =
				IntegerSubChip::<W, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_mul =
				IntegerMulChip::<W, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_div =
				IntegerDivChip::<W, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);

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
			&self, config: Self::Config, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let aggregator_chipset =
				AggregatorChipset::<E, NUM_LIMBS, NUM_BITS, P, SpongeHasher, PoseidonNativeSponge, EC>::new(
					self.svk,
					self.snarks.clone(),
					self.as_proof.clone(),
				);
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

	// #[ignore = "Aggregator takes too long to run"]
	#[test]
	fn test_aggregator() {
		// Testing Aggregator
		let rng = &mut thread_rng();
		let k = 21;
		let params = generate_params::<E>(k);

		let random_circuit_1 = MulChip::new(Scalar::one(), Scalar::one());
		// let random_circuit_2 = MulChip::new(Scalar::one(), Scalar::one());

		let instances_1: Vec<Vec<Scalar>> = vec![vec![Scalar::one()]];
		// let instances_2: Vec<Vec<Scalar>> = vec![vec![Scalar::one()]];

		let snark_1 = Snark::new(&params, random_circuit_1, instances_1, rng);
		// let snark_2 = Snark::new(&params, random_circuit_2, instances_2, rng);

		// let snarks = vec![snark_1, snark_2];
		let snarks = vec![snark_1];
		let NativeAggregator { svk, snarks, instances, as_proof, .. } =
			NativeAggregator::new(&params, snarks);

		let aggregator_circuit = AggregatorTestCircuit::new(svk, snarks, as_proof);
		let prover = MockProver::run(k, &aggregator_circuit, vec![instances]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	// #[ignore = "Et Aggregator takes too long to run"]
	#[test]
	fn test_et_aggregator_prod() {
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;
		const DOMAIN: u128 = 42;

		let ops: Vec<Vec<Scalar>> = vec![
			vec![0, 200, 300, 500],
			vec![100, 0, 600, 300],
			vec![400, 100, 0, 500],
			vec![100, 200, 700, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| Scalar::from_u128(x)).collect())
		.collect();

		let (opt_att, opt_pks, et_circuit_pi) = eigen_trust_set_testing_helper::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			DOMAIN,
		>(ops);

		// Prepare the Aggregator input
		let NativeAggregator { svk, snarks, instances, as_proof, .. } = {
			let rng = &mut thread_rng();
			let k = 20;
			let params = generate_params::<Bn256>(k);

			let et_circuit = EigenTrust4::new(opt_att, opt_pks, Fr::from_u128(DOMAIN));
			let et_circuit_instances: Vec<Vec<Fr>> = vec![et_circuit_pi];
			let snark_1 = Snark::<Bn256, NUM_LIMBS, NUM_BITS, P, S, EC>::new(
				&params, et_circuit, et_circuit_instances, rng,
			);

			let snarks = vec![snark_1];
			NativeAggregator::new(&params, snarks)
		};

		let k = 21;
		let rng = &mut thread_rng();
		let aggregator_circuit = AggregatorTestCircuit::new(svk, snarks, as_proof);
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, aggregator_circuit, &[&instances], rng)
			.unwrap();
		assert!(res);
	}
}
