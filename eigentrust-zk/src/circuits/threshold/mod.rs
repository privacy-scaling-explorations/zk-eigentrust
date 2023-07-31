use crate::{
	ecc::{
		AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
		EccUnreducedLadderConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualChipset, LessEqualConfig, NShiftedChip},
		main::{InverseChipset, IsZeroChipset, MainChip, MainConfig, MulAddChipset, MulChipset},
		set::{SelectItemChip, SetPositionChip},
	},
	integer::{IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip, IntegerSubChip},
	params::rns::bn256::Bn256_4_68,
	poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
	verifier::{
		aggregator::{native::Snark, AggregatorChipset, AggregatorConfig, Svk, UnassignedSnark},
		transcript::native::WIDTH,
	},
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	arithmetic::Field,
	circuit::{Layouter, SimpleFloorPlanner, Value},
	halo2curves::{
		bn256::{Fq, Fr},
		ff::PrimeField,
	},
	plonk::{Circuit, ConstraintSystem, Error, Selector},
};
use itertools::Itertools;

use super::{
	dynamic_sets::ecdsa_native::{NUM_BITS, NUM_LIMBS},
	FullRoundHasher, PartialRoundHasher,
};

/// Native version of checking score threshold
pub mod native;

#[derive(Clone, Debug)]
/// The columns config for the Threshold circuit.
pub struct ThresholdCircuitConfig {
	common: CommonConfig,
	main: MainConfig,
	lt_eq: LessEqualConfig,
	aggregator: AggregatorConfig,
	set_pos_selector: Selector,
	select_item_selector: Selector,
}

#[derive(Clone, Debug)]
/// Structure of the EigenTrustSet circuit
pub struct ThresholdCircuit<
	const POWER_OF_TEN: usize,
	const NUM_NEIGHBOURS: usize,
	const INITIAL_SCORE: u128,
> {
	sets: Vec<Value<Fr>>,
	scores: Vec<Value<Fr>>,
	num_decomposed: Vec<Value<Fr>>,
	den_decomposed: Vec<Value<Fr>>,

	svk: Svk,
	snarks: Vec<UnassignedSnark>,
	as_proof: Option<Vec<u8>>,
}

impl<const POWER_OF_TEN: usize, const NUM_NEIGHBOURS: usize, const INITIAL_SCORE: u128>
	ThresholdCircuit<POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>
{
	/// Constructs a new ThresholdCircuit
	pub fn new(
		sets: &[Fr], scores: &[Fr], num_decomposed: &[Fr], den_decomposed: &[Fr], svk: Svk,
		snarks: Vec<Snark>, as_proof: Vec<u8>,
	) -> Self {
		let sets = sets.iter().map(|s| Value::known(*s)).collect();
		let scores = scores.iter().map(|s| Value::known(*s)).collect();
		let num_decomposed = (0..NUM_LIMBS).map(|i| Value::known(num_decomposed[i])).collect();
		let den_decomposed = (0..NUM_LIMBS).map(|i| Value::known(den_decomposed[i])).collect();

		let snarks = snarks.into_iter().map_into().collect();
		let as_proof = Some(as_proof);
		Self { sets, scores, den_decomposed, num_decomposed, svk, snarks, as_proof }
	}
}

impl<const POWER_OF_TEN: usize, const NUM_NEIGHBOURS: usize, const INITIAL_SCORE: u128> Circuit<Fr>
	for ThresholdCircuit<POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>
{
	type Config = ThresholdCircuitConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		let sets = (0..NUM_NEIGHBOURS).map(|_| Value::unknown()).collect();
		let scores = (0..NUM_NEIGHBOURS).map(|_| Value::unknown()).collect();
		let num_decomposed = (0..NUM_LIMBS).map(|_| Value::unknown()).collect();
		let den_decomposed = (0..NUM_LIMBS).map(|_| Value::unknown()).collect();

		let svk = self.svk;
		let snarks = self.snarks.iter().map(UnassignedSnark::without_witness).collect();
		let as_proof = None;
		Self { sets, scores, num_decomposed, den_decomposed, svk, snarks, as_proof }
	}

	fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let bits_2_num_selector = Bits2NumChip::configure(&common, meta);
		let n_shifted_selector = NShiftedChip::configure(&common, meta);
		let lt_eq = LessEqualConfig::new(main.clone(), bits_2_num_selector, n_shifted_selector);

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
		let ecc_mul_scalar = EccMulConfig::new(ladder, add, double.clone(), table_select, bits2num);
		let aux = AuxConfig::new(double);

		let aggregator =
			AggregatorConfig { main: main.clone(), poseidon_sponge, ecc_mul_scalar, aux };

		let set_pos_selector = SetPositionChip::configure(&common, meta);
		let select_item_selector = SelectItemChip::configure(&common, meta);

		ThresholdCircuitConfig {
			common,
			main,
			lt_eq,
			aggregator,
			set_pos_selector,
			select_item_selector,
		}
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
	) -> Result<(), Error> {
		let (
			num_neighbor,
			init_score,
			max_limb_value,
			one,
			zero,
			sets,
			scores,
			target_addr,
			threshold,
			expected_check_res,
		) = layouter.assign_region(
			|| "temp",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				// constants
				let num_neighbor = ctx.assign_from_constant(
					config.common.advice[0],
					Fr::from_u128(NUM_NEIGHBOURS as u128),
				)?;
				let init_score = ctx
					.assign_from_constant(config.common.advice[1], Fr::from_u128(INITIAL_SCORE))?;
				let max_limb_value = ctx.assign_from_constant(
					config.common.advice[2],
					Fr::from_u128(10_u128).pow([POWER_OF_TEN as u64]),
				)?;
				let one = ctx.assign_from_constant(config.common.advice[5], Fr::ONE)?;
				let zero = ctx.assign_from_constant(config.common.advice[6], Fr::ZERO)?;

				// Public input
				let target_addr =
					ctx.assign_from_instance(config.common.advice[7], config.common.instance, 0)?;
				let threshold =
					ctx.assign_from_instance(config.common.advice[8], config.common.instance, 1)?;
				let expected_check_res =
					ctx.assign_from_instance(config.common.advice[9], config.common.instance, 2)?;

				ctx.next();

				// private inputs - sets & scores
				let mut sets = vec![];
				for i in 0..NUM_NEIGHBOURS {
					let member =
						ctx.assign_advice(config.common.advice[i % ADVICE], self.sets[i])?;
					sets.push(member);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				ctx.next();

				let mut scores = vec![];
				for i in 0..NUM_NEIGHBOURS {
					let score =
						ctx.assign_advice(config.common.advice[i % ADVICE], self.scores[i])?;
					scores.push(score);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}

				Ok((
					num_neighbor, init_score, max_limb_value, one, zero, sets, scores, target_addr,
					threshold, expected_check_res,
				))
			},
		)?;

		// check every element of "num_decomposed"
		let num_decomposed_limbs = layouter.assign_region(
			|| "num_decomposed",
			|region| {
				let mut limbs = vec![];

				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..self.num_decomposed.len() {
					let limb = ctx
						.assign_advice(config.common.advice[i % ADVICE], self.num_decomposed[i])?;
					limbs.push(limb);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}

				Ok(limbs)
			},
		)?;

		// check every element of "den_decomposed"
		let den_decomposed_limbs = layouter.assign_region(
			|| "den_decomposed",
			|region| {
				let mut limbs = vec![];

				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..self.den_decomposed.len() {
					let limb = ctx
						.assign_advice(config.common.advice[i % ADVICE], self.den_decomposed[i])?;
					limbs.push(limb);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				Ok(limbs)
			},
		)?;

		// verify if the "sets" & "scores" are valid, using aggregation verify
		// TODO: Uncomment when the aggregator bug is fixed.
		//
		// let aggregator =
		// 	AggregatorChipset::new(self.svk, self.snarks.clone(), self.as_proof.clone());
		// let _agg_proof = aggregator.synthesize(
		// 	&config.common,
		// 	&config.aggregator,
		// 	layouter.namespace(|| "aggregator chipset"),
		// )?;
		// for i in 0..16_usize {
		// 	layouter.constrain_instance(
		// 		agg_proof[i].cell(),
		// 		config.common.instance,
		// 		3_usize + i, // 3 rows are taken by "target_addr", "threshold", "native_threshold_check"
		// 	)?;
		// }

		// obtain the score of "target_addr" from "scores", using SetPositionChip & SelectItemChip
		let set_pos_chip = SetPositionChip::new(sets, target_addr);
		let target_addr_idx = set_pos_chip.synthesize(
			&config.common,
			&config.set_pos_selector,
			layouter.namespace(|| "target_addr_idx"),
		)?;
		let select_item_chip = SelectItemChip::new(scores, target_addr_idx);
		let score = select_item_chip.synthesize(
			&config.common,
			&config.select_item_selector,
			layouter.namespace(|| "target_addr_score"),
		)?;

		// max_score = NUM_NEIGHBOURS * INITIAL_SCORE
		let mul_chipset = MulChipset::new(num_neighbor, init_score);
		let max_score = mul_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "NUM_NEIGHBOURS * INITIAL_SCORE"),
		)?;

		// assert!(threshold < max_score)
		let lt_eq_chipset = LessEqualChipset::new(threshold.clone(), max_score);
		let res = lt_eq_chipset.synthesize(
			&config.common,
			&config.lt_eq,
			layouter.namespace(|| "threshold < max_score"),
		)?;
		layouter.assign_region(
			|| "res == 1",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
				ctx.constrain_equal(res, one)?;

				Ok(())
			},
		)?;

		for i in 0..num_decomposed_limbs.len() {
			// assert!(limb < max_limb_value)
			let lt_eq_chipset =
				LessEqualChipset::new(num_decomposed_limbs[i].clone(), max_limb_value.clone());
			let res = lt_eq_chipset.synthesize(
				&config.common,
				&config.lt_eq,
				layouter.namespace(|| "(num_decomposed) limb < max_limb_value"),
			)?;
			layouter.assign_region(
				|| "res == 1",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
					let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
					ctx.constrain_equal(res, one)?;

					Ok(())
				},
			)?;
		}

		for i in 0..den_decomposed_limbs.len() {
			// assert!(limb < max_limb_value)
			let lt_eq_chipset =
				LessEqualChipset::new(den_decomposed_limbs[i].clone(), max_limb_value.clone());
			let res = lt_eq_chipset.synthesize(
				&config.common,
				&config.lt_eq,
				layouter.namespace(|| "(den_decomposed) limb < max_limb_value"),
			)?;
			layouter.assign_region(
				|| "res == 1",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
					let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
					ctx.constrain_equal(res, one)?;

					Ok(())
				},
			)?;
		}

		// composed_num * composed_den_inv == score
		let composed_num = {
			let mut limbs = num_decomposed_limbs.clone();
			limbs.reverse();
			let scale = max_limb_value.clone();

			let mut val = limbs[0].clone();
			for i in 1..NUM_LIMBS {
				let mul_add_chipset = MulAddChipset::new(val, scale.clone(), limbs[i].clone());
				val = mul_add_chipset.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "val * scale + limb"),
				)?;
			}

			val
		};

		let composed_den = {
			let mut limbs = den_decomposed_limbs.clone();
			limbs.reverse();
			let scale = max_limb_value;

			let mut val = limbs[0].clone();
			for i in 1..NUM_LIMBS {
				let mul_add_chipset = MulAddChipset::new(val, scale.clone(), limbs[i].clone());
				val = mul_add_chipset.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "val * scale + limb"),
				)?;
			}

			val
		};

		let inv_chipset = InverseChipset::new(composed_den);
		let composed_den_inv = inv_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "composed_den ^ -1"),
		)?;

		let mul_chipset = MulChipset::new(composed_num, composed_den_inv);
		let res = mul_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "composed_num * composed_den_inv"),
		)?;
		layouter.assign_region(
			|| "res == score",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let score = ctx.copy_assign(config.common.advice[1], score.clone())?;
				ctx.constrain_equal(res, score)?;

				Ok(())
			},
		)?;

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let last_limb_num = num_decomposed_limbs.last().unwrap();
		let last_limb_den = den_decomposed_limbs.last().unwrap();

		// assert!(last_limb_den != 0)
		let is_zero_chipset = IsZeroChipset::new(last_limb_den.clone());
		let res = is_zero_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "last_limb_den != 0"),
		)?;
		layouter.assign_region(
			|| "res == 0",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let zero = ctx.copy_assign(config.common.advice[1], zero.clone())?;
				ctx.constrain_equal(res, zero)?;

				Ok(())
			},
		)?;

		let mul_chipset = MulChipset::new(last_limb_den.clone(), threshold);
		let comp = mul_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "last_limb_den * threshold"),
		)?;

		let lt_eq_chipset = LessEqualChipset::new(comp, last_limb_num.clone());
		let threshold_check_res = lt_eq_chipset.synthesize(
			&config.common,
			&config.lt_eq,
			layouter.namespace(|| "comp <= last_limb_num"),
		)?;

		// final constraint
		layouter.assign_region(
			|| "threshold_check_res == expected_check_res",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let threshold_check_res =
					ctx.copy_assign(config.common.advice[0], threshold_check_res.clone())?;
				let expected_check_res =
					ctx.copy_assign(config.common.advice[1], expected_check_res.clone())?;
				ctx.constrain_equal(threshold_check_res, expected_check_res)?;

				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		circuits::{
			dynamic_sets::native::{Attestation, EigenTrustSet, SignedAttestation},
			threshold::native::Threshold,
			PoseidonNativeHasher, PoseidonNativeSponge, HASHER_WIDTH,
		},
		ecdsa::native::{EcdsaKeypair, PublicKey},
		params::{
			ecc::secp256k1::Secp256k1Params,
			rns::{decompose_big_decimal, secp256k1::Secp256k1_4_68},
		},
		utils::{big_to_fe, fe_to_big, generate_params},
		verifier::aggregator::native::NativeAggregator,
	};
	use halo2::{
		arithmetic::Field,
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			ff::PrimeField,
			secp256k1::Secp256k1Affine,
		},
	};
	use num_bigint::BigInt;
	use num_rational::BigRational;
	use rand::thread_rng;

	const DOMAIN: u128 = 42;
	type C = Secp256k1Affine;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;
	type H = PoseidonNativeHasher;
	type SH = PoseidonNativeSponge;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		keypair: &EcdsaKeypair<C, N, NUM_LIMBS, NUM_BITS, P, EC>, pks: &[N], scores: &[N],
	) -> Vec<Option<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);
		let rng = &mut thread_rng();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i] == N::zero() {
				res.push(None)
			} else {
				let (about, key, value, message) =
					(pks[i], N::from_u128(DOMAIN), scores[i], N::zero());
				let attestation = Attestation::new(about, key, value, message);
				let msg = big_to_fe(fe_to_big(attestation.hash::<HASHER_WIDTH, H>()));
				let signature = keypair.sign(msg, rng);
				let signed_attestation = SignedAttestation::new(attestation, signature);

				res.push(Some(signed_attestation));
			}
		}
		res
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		ops: Vec<Vec<N>>,
	) -> (Vec<N>, Vec<N>, Vec<BigRational>) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypairs: Vec<EcdsaKeypair<C, _, NUM_LIMBS, NUM_BITS, _, _>> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| EcdsaKeypair::generate_keypair(rng)).collect();

		let pks: Vec<PublicKey<C, _, NUM_LIMBS, NUM_BITS, _, _>> =
			keypairs.iter().map(|kp| kp.public_key.clone()).collect();

		let pks_fr: Vec<N> = keypairs.iter().map(|kp| kp.public_key.to_address()).collect();

		// Add the "address"(pk_fr) to the set
		pks_fr.iter().for_each(|pk| set.add_member(*pk));

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();
			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&keypairs[i], &pks_fr, &scores,
			);
			set.update_op(pks[i].clone(), op_i);
		}

		let s = set.converge();
		let s_ratios = set.converge_rational();

		(pks_fr, s, s_ratios)
	}

	fn ratio_to_decomposed_helper<const NUM_LIMBS: usize, const POWER_OF_TEN: usize>(
		ratio: BigRational,
	) -> ([Fr; NUM_LIMBS], [Fr; NUM_LIMBS]) {
		let num = ratio.numer();
		let den = ratio.denom();
		let max_len = NUM_LIMBS * POWER_OF_TEN;
		let bigger = num.max(den);
		let dig_len = bigger.to_string().len();
		let diff = max_len - dig_len;

		let scale = BigInt::from(10_u32).pow(diff as u32);
		let num_scaled = num * scale.clone();
		let den_scaled = den * scale;
		let num_scaled_uint = num_scaled.to_biguint().unwrap();
		let den_scaled_uint = den_scaled.to_biguint().unwrap();

		let num_decomposed = decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(num_scaled_uint);
		let den_decomposed = decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(den_scaled_uint);

		(num_decomposed, den_decomposed)
	}

	#[ignore = "EigenTrustSet(ecdsa) circuit is not ready & aggregator has a bug."]
	#[test]
	fn test_threshold_circuit() {
		// Test Threshold Circuit
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 72;

		let ops: Vec<Vec<N>> = vec![
			vec![0, 200, 300, 500],
			vec![100, 0, 600, 300],
			vec![400, 100, 0, 500],
			vec![100, 200, 700, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| N::from_u128(x)).collect())
		.collect();

		let (sets, scores, score_ratios) =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let target_idx = 2;

		let target_addr = sets[target_idx].clone();
		let score = scores[target_idx].clone();
		let score_ratio = score_ratios[target_idx].clone();
		let (num_decomposed, den_decomposed) =
			ratio_to_decomposed_helper::<NUM_LIMBS, POWER_OF_TEN>(score_ratio.clone());
		let threshold = Fr::from_u128(1000_u128);

		let native_threshold: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			Threshold::new(score, score_ratio, threshold);
		let native_threshold_check =
			if native_threshold.check_threshold() { N::ONE } else { N::ZERO };

		// Prepare the aggregator inputs
		let _rng = &mut thread_rng();
		let k = 21;
		let params = generate_params::<Bn256>(k);

		// let ecdsa_et_circuit = EigenTrustSet::new();
		// let instances_1: Vec<Vec<Fr>> = vec![scores.clone()];
		// let snark_1 = Snark::new(&params, ecdsa_et_circuit, instances_1, rng);
		// let snarks = vec![snark_1];

		// TODO: Replace "mock_snarks" with "snarks" when "EigenTrustSet"(ecdsa) circuit is implemented & aggregator bug is fixed.
		let mock_snarks = vec![];
		let NativeAggregator { svk, snarks, instances, as_proof } =
			NativeAggregator::new(&params, mock_snarks);

		// Threshold circuit testing
		let mut pub_ins = vec![target_addr, threshold, native_threshold_check];
		pub_ins.extend(instances);

		let threshold_circuit: ThresholdCircuit<POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			ThresholdCircuit::new(
				&sets, &scores, &num_decomposed, &den_decomposed, svk, snarks, as_proof,
			);

		let k = 12;
		let prover = match MockProver::<N>::run(k, &threshold_circuit, vec![pub_ins]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_threshold_circuit_prod() {
		// Test Threshold Circuit production
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 72;

		let ops: Vec<Vec<N>> = vec![
			vec![0, 200, 300, 500],
			vec![100, 0, 600, 300],
			vec![400, 100, 0, 500],
			vec![100, 200, 700, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| N::from_u128(x)).collect())
		.collect();

		let (sets, scores, score_ratios) =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let target_idx = 2;

		let target_addr = sets[target_idx].clone();
		let score = scores[target_idx].clone();
		let score_ratio = score_ratios[target_idx].clone();
		let (num_decomposed, den_decomposed) =
			ratio_to_decomposed_helper::<N, NUM_LIMBS, POWER_OF_TEN>(score_ratio.clone());
		let threshold = N::from_u128(1000_u128);

		let native_threshold: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			Threshold::new(score, score_ratio, threshold);
		let native_threshold_check =
			if native_threshold.check_threshold() { N::ONE } else { N::ZERO };

		let pub_ins = vec![target_addr, threshold, native_threshold_check];

		let threshold_circuit: ThresholdCircuit<
			N,
			NUM_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
		> = ThresholdCircuit::new(&sets, &scores, &num_decomposed, &den_decomposed);

		let k = 12;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, threshold_circuit, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
