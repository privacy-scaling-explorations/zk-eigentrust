use crate::{
	integer::native::Integer,
	params::hasher::poseidon_bn254_5x5::Params,
	params::rns::bn256::Bn256_4_68,
	poseidon::native::sponge::PoseidonSponge,
	verifier::{
		gen_pk,
		loader::native::{NUM_BITS, NUM_LIMBS},
		transcript::native::{NativeTranscriptRead, NativeTranscriptWrite, WIDTH},
	},
};
use halo2::{
	circuit::Value,
	halo2curves::bn256::{Bn256, Fr, G1Affine},
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
	verifier::{plonk::PlonkProtocol, SnarkVerifier},
};

use super::{Aggregator, Psv};

#[derive(Clone)]
/// Snark structure
pub struct Snark {
	/// Protocol
	pub protocol: PlonkProtocol<G1Affine>,
	/// Instances
	pub instances: Vec<Vec<Fr>>,
	/// Proof
	pub proof: Vec<u8>,
}

impl Snark {
	/// Create a new Snark
	pub fn new<C: Circuit<Fr>, R: RngCore>(
		params: &ParamsKZG<Bn256>, circuit: C, instances: Vec<Vec<Fr>>, rng: &mut R,
	) -> Self {
		let pk = gen_pk(params, &circuit);
		let config = Config::kzg().with_num_instance(vec![instances.len()]);

		let protocol = compile(params, pk.get_vk(), config);

		let instances_slice: Vec<&[Fr]> = instances.iter().map(|x| x.as_slice()).collect();
		let mut transcript = NativeTranscriptWrite::<
			_,
			G1Affine,
			Bn256_4_68,
			PoseidonSponge<Fr, WIDTH, Params>,
		>::new(Vec::new());
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

impl Aggregator {
	/// Create a new aggregator.
	pub fn new(params: &ParamsKZG<Bn256>, snarks: Vec<Snark>) -> Self {
		let svk = params.get_g()[0].into();

		let mut plonk_proofs = Vec::new();
		for snark in &snarks {
			let mut transcript_read: NativeTranscriptRead<
				_,
				G1Affine,
				Bn256_4_68,
				PoseidonSponge<Fr, WIDTH, Params>,
			> = NativeTranscriptRead::init(snark.proof.as_slice());

			let proof = Psv::read_proof(
				&svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = Psv::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap();

			plonk_proofs.extend(res);
		}

		let mut transcript_write = NativeTranscriptWrite::<
			Vec<u8>,
			G1Affine,
			Bn256_4_68,
			PoseidonSponge<Fr, WIDTH, Params>,
		>::new(Vec::new());
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
		let accumulator_limbs = [lhs.x, lhs.y, rhs.x, rhs.y]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, Bn256_4_68>::from_w(v).limbs)
			.concat();

		Self {
			svk,
			snarks: snarks.into_iter().map_into().collect(),
			instances: accumulator_limbs,
			as_proof: Some(as_proof),
		}
	}

	/// Verify accumulators
	pub fn verify(&self, snark_instances: Vec<Vec<Vec<Fr>>>) {
		assert!(self.snarks.len() == snark_instances.len());
		for i in 0..self.snarks.len() {
			// Extra check with instances
			let _: Vec<Vec<()>> = self.snarks[i]
				.instances
				.iter()
				.zip(snark_instances[i].iter())
				.map(|(x, y)| {
					x.iter().zip(y.iter()).map(|(a, b)| a.assert_if_known(|a| a == b)).collect()
				})
				.collect();
		}

		let mut accumulators = Vec::new();
		for (i, snark) in self.snarks.iter().enumerate() {
			let snark_proof = snark.proof.clone().unwrap();
			let snark_proof = snark_proof.as_slice();
			let mut transcript_read: NativeTranscriptRead<
				_,
				G1Affine,
				Bn256_4_68,
				PoseidonSponge<Fr, WIDTH, Params>,
			> = NativeTranscriptRead::init(snark_proof.clone());
			let proof = Psv::read_proof(
				&self.svk, &snark.protocol, &snark_instances[i], &mut transcript_read,
			)
			.unwrap();
			let res = Psv::verify(&self.svk, &snark.protocol, &snark_instances[i], &proof).unwrap();
			accumulators.extend(res);
		}

		let as_proof = self.as_proof.clone().unwrap();
		let as_proof = as_proof.as_slice();
		let mut transcript: NativeTranscriptRead<
			_,
			G1Affine,
			Bn256_4_68,
			PoseidonSponge<Fr, WIDTH, Params>,
		> = NativeTranscriptRead::init(as_proof);
		let proof =
			KzgAs::<Bn256, Gwc19>::read_proof(&Default::default(), &accumulators, &mut transcript)
				.unwrap();

		let accumulator =
			KzgAs::<Bn256, Gwc19>::verify(&Default::default(), &accumulators, &proof).unwrap();

		let KzgAccumulator { lhs, rhs } = accumulator;
		let accumulator_limbs = [lhs.x, lhs.y, rhs.x, rhs.y]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, Bn256_4_68>::from_w(v).limbs)
			.concat();

		assert!(self.instances == accumulator_limbs);
	}
}

#[cfg(test)]
mod test {

	use super::{Aggregator, Snark};
	use crate::{utils::generate_params, CommonConfig, RegionCtx};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
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

	#[test]
	fn test_aggregator_native() {
		// Testing Aggregator
		let rng = &mut thread_rng();
		let k = 21;
		let params = generate_params::<Bn256>(k);

		let random_circuit_1 = MulChip::new(Fr::one(), Fr::one());
		let random_circuit_2 = MulChip::new(Fr::one(), Fr::one());

		let instances_1: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
		let instances_2: Vec<Vec<Fr>> = vec![vec![Fr::one()]];

		let snark_1 = Snark::new(&params, random_circuit_1, instances_1.clone(), rng);
		let snark_2 = Snark::new(&params, random_circuit_2, instances_2.clone(), rng);

		let snarks = vec![snark_1, snark_2];
		let aggregator = Aggregator::new(&params, snarks);

		aggregator.verify(vec![instances_1, instances_2]);
	}
}
