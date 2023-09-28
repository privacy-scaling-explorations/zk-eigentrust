use std::{fmt::Debug, marker::PhantomData};

use super::{Psv, Svk};
use crate::{
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	verifier::{
		gen_pk,
		transcript::native::{NativeTranscriptRead, NativeTranscriptWrite},
	},
	FieldExt, SpongeHasher,
};
use halo2::{
	halo2curves::{
		ff::WithSmallOrderMulGroup, pairing::MultiMillerLoop, serde::SerdeObject, CurveAffine,
	},
	plonk::{create_proof, Circuit},
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
		kzg::{Gwc19, KzgAccumulator, KzgAs},
		AccumulationScheme, AccumulationSchemeProver,
	},
	system::halo2::{compile, Config},
	verifier::{
		plonk::{PlonkProtocol, PlonkSuccinctVerifier},
		SnarkVerifier,
	},
};

#[derive(Clone)]
/// Snark structure
pub struct Snark<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, EC>
where
	E: MultiMillerLoop,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt,
{
	/// Protocol
	pub protocol: PlonkProtocol<E::G1Affine>,
	/// Instances
	pub instances: Vec<Vec<E::Scalar>>,
	/// Proof
	pub proof: Vec<u8>,
	/// Phantom Datas
	_p: PhantomData<(P, S, EC, E)>,
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, EC>
	Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>
where
	E: MultiMillerLoop + Debug,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt + WithSmallOrderMulGroup<3>,
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	/// Create a new Snark
	pub fn new<C: Circuit<E::Scalar>, R: RngCore>(
		params: &ParamsKZG<E>, circuit: C, instances: Vec<Vec<E::Scalar>>, rng: &mut R,
	) -> Self {
		let pk = gen_pk(params, &circuit);
		let inst_len = instances.iter().map(|x| x.len()).collect_vec();
		let config = Config::kzg().with_num_instance(inst_len);

		let protocol = compile(params, pk.get_vk(), config);

		let instances_slice: Vec<&[E::Scalar]> = instances.iter().map(|x| x.as_slice()).collect();
		let mut transcript =
			NativeTranscriptWrite::<_, E::G1Affine, NUM_LIMBS, NUM_BITS, P, S>::new(Vec::new());
		create_proof::<KZGCommitmentScheme<E>, ProverGWC<_>, _, _, _, _>(
			params,
			&pk,
			&[circuit],
			&[instances_slice.as_slice()],
			rng,
			&mut transcript,
		)
		.unwrap();
		let proof = transcript.finalize();

		Self { protocol, instances, proof, _p: PhantomData }
	}
}

/// Native Aggregator
#[derive(Clone)]
pub struct NativeAggregator<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, EC>
where
	E: MultiMillerLoop + Debug,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt + WithSmallOrderMulGroup<3>,
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	/// Succinct Verifying Key
	pub svk: Svk<E::G1Affine>,
	/// Snarks for the aggregation
	pub snarks: Vec<Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>>,
	/// Instances
	pub instances: Vec<E::Scalar>,
	/// Accumulation Scheme Proof
	pub as_proof: Vec<u8>,
	// Phantom Data
	_p: PhantomData<(P, S, EC, E)>,
}

impl<E, const NUM_LIMBS: usize, const NUM_BITS: usize, P, S, EC>
	NativeAggregator<E, NUM_LIMBS, NUM_BITS, P, S, EC>
where
	E: MultiMillerLoop + Debug,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	S: SpongeHasher<E::Scalar>,
	EC: EccParams<E::G1Affine>,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	E::Scalar: FieldExt + WithSmallOrderMulGroup<3>,
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	/// Create a new aggregator.
	pub fn new(
		params: &ParamsKZG<E>, snarks: Vec<Snark<E, NUM_LIMBS, NUM_BITS, P, S, EC>>,
	) -> Self {
		let svk = params.get_g()[0].into();

		let mut plonk_proofs = Vec::new();
		for snark in &snarks {
			let mut transcript_read: NativeTranscriptRead<
				_,
				E::G1Affine,
				NUM_LIMBS,
				NUM_BITS,
				P,
				S,
			> = NativeTranscriptRead::init(snark.proof.as_slice());

			let proof = Psv::<E>::read_proof(
				&svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = Psv::<E>::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap();

			plonk_proofs.extend(res);
		}

		let mut transcript_write =
			NativeTranscriptWrite::<Vec<u8>, E::G1Affine, NUM_LIMBS, NUM_BITS, P, S>::new(
				Vec::new(),
			);
		let rng = &mut thread_rng();
		let accumulator = KzgAs::<E, Gwc19>::create_proof(
			&Default::default(),
			&plonk_proofs,
			&mut transcript_write,
			rng,
		)
		.unwrap();
		let as_proof = transcript_write.finalize();

		let KzgAccumulator { lhs, rhs } = accumulator;
		let lhs_coord = lhs.coordinates().unwrap();
		let rhs_coord = rhs.coordinates().unwrap();
		let accumulator_limbs = [*lhs_coord.x(), *lhs_coord.y(), *rhs_coord.x(), *rhs_coord.y()]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(v).limbs)
			.concat();

		Self { svk, snarks, instances: accumulator_limbs, as_proof, _p: PhantomData }
	}

	/// Verify accumulators
	pub fn verify(&self) {
		let mut accumulators = Vec::new();
		for snark in self.snarks.iter() {
			let snark_proof = snark.proof.clone();
			let mut transcript_read: NativeTranscriptRead<
				_,
				E::G1Affine,
				NUM_LIMBS,
				NUM_BITS,
				P,
				S,
			> = NativeTranscriptRead::init(snark_proof.as_slice());
			let proof = PlonkSuccinctVerifier::<KzgAs<E, Gwc19>>::read_proof(
				&self.svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = PlonkSuccinctVerifier::<KzgAs<E, Gwc19>>::verify(
				&self.svk, &snark.protocol, &snark.instances, &proof,
			)
			.unwrap();
			accumulators.extend(res);
		}

		let as_proof = self.as_proof.clone();
		let mut transcript: NativeTranscriptRead<_, E::G1Affine, NUM_LIMBS, NUM_BITS, P, S> =
			NativeTranscriptRead::init(as_proof.as_slice());
		let proof =
			KzgAs::<E, Gwc19>::read_proof(&Default::default(), &accumulators, &mut transcript)
				.unwrap();

		let accumulator =
			KzgAs::<E, Gwc19>::verify(&Default::default(), &accumulators, &proof).unwrap();

		let KzgAccumulator { lhs, rhs } = accumulator;
		let lhs_coord = lhs.coordinates().unwrap();
		let rhs_coord = rhs.coordinates().unwrap();
		let accumulator_limbs = [*lhs_coord.x(), *lhs_coord.y(), *rhs_coord.x(), *rhs_coord.y()]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, P>::from_w(v).limbs)
			.concat();

		assert!(self.instances == accumulator_limbs);
	}
}

#[cfg(test)]
mod test {
	use super::{NativeAggregator, Snark};
	use crate::{
		circuits::PoseidonNativeSponge,
		params::{ecc::bn254::Bn254Params, rns::bn256::Bn256_4_68},
		utils::generate_params,
		CommonConfig, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem, Error},
		poly::Rotation,
	};
	use rand::thread_rng;

	type Scalar = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;

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
	fn test_native_aggregator() {
		// Testing Aggregator
		let rng = &mut thread_rng();
		let k = 12;
		let params = generate_params::<Bn256>(k);

		let random_circuit_1 = MulChip::new(Fr::one(), Fr::one());
		let random_circuit_2 = MulChip::new(Fr::one(), Fr::one());

		let instances_1: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
		let instances_2: Vec<Vec<Fr>> = vec![vec![Fr::one()]];

		let snark_1 = Snark::<
			Bn256,
			NUM_LIMBS,
			NUM_BITS,
			Bn256_4_68,
			PoseidonNativeSponge,
			Bn254Params,
		>::new(&params, random_circuit_1, instances_1.clone(), rng);
		let snark_2 = Snark::new(&params, random_circuit_2, instances_2.clone(), rng);

		let snarks = vec![snark_1, snark_2];
		let native_aggregator = NativeAggregator::new(&params, snarks);

		// Should pass the assertion
		native_aggregator.verify();
	}
}
