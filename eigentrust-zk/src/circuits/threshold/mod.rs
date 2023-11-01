use std::marker::PhantomData;

use super::HASHER_WIDTH;
use crate::{
	ecc::{
		AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
		EccUnreducedLadderConfig,
	},
	gadgets::{
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualChipset, LessEqualConfig, NShiftedChip},
		main::{InverseChipset, IsZeroChipset, MainChip, MainConfig, MulAddChipset, MulChipset},
		set::{SelectItemChip, SetPositionChip},
	},
	integer::{IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip, IntegerSubChip},
	params::{ecc::EccParams, hasher::RoundParams, rns::RnsParams},
	verifier::aggregator::{
		native::Snark, AggregatorChipset, AggregatorConfig, Svk, UnassignedSnark,
	},
	Chip, Chipset, CommonConfig, FieldExt, RegionCtx, SpongeHasher, SpongeHasherChipset, ADVICE,
};
use halo2::{
	arithmetic::Field,
	circuit::{Layouter, SimpleFloorPlanner, Value},
	halo2curves::{ff::PrimeField, CurveAffine},
	plonk::{Circuit, ConstraintSystem, Error, Selector},
};
use snark_verifier::util::arithmetic::MultiMillerLoop;

/// Native version of checking score threshold
pub mod native;

#[derive(Clone, Debug)]
/// The columns config for the Threshold circuit.
pub struct ThresholdCircuitConfig<F: FieldExt, S>
where
	S: SpongeHasherChipset<F>,
{
	common: CommonConfig,
	main: MainConfig,
	lt_eq: LessEqualConfig,
	aggregator: AggregatorConfig<F, S>,
	set_pos_selector: Selector,
	select_item_selector: Selector,
}

#[derive(Clone, Debug)]
/// Structure of the EigenTrustSet circuit
pub struct ThresholdCircuit<
	E: MultiMillerLoop,
	const NUM_DECIMAL_LIMBS: usize,
	const POWER_OF_TEN: usize,
	const NUM_NEIGHBOURS: usize,
	const INITIAL_SCORE: u128,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
	S,
	H,
	R,
> where
	E::Scalar: FieldExt,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<E::G1Affine>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	R: RoundParams<E::Scalar, HASHER_WIDTH>,
{
	sets: Vec<Value<E::Scalar>>,
	scores: Vec<Value<E::Scalar>>,
	num_decomposed: Vec<Value<E::Scalar>>,
	den_decomposed: Vec<Value<E::Scalar>>,

	svk: Svk<E::G1Affine>,
	snarks: Vec<UnassignedSnark<E>>,
	as_proof: Option<Vec<u8>>,

	_p: PhantomData<(P, EC, S, H, R)>,
}

impl<
		E: MultiMillerLoop,
		const NUM_DECIMAL_LIMBS: usize,
		const POWER_OF_TEN: usize,
		const NUM_NEIGHBOURS: usize,
		const INITIAL_SCORE: u128,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		S,
		H,
		R,
	>
	ThresholdCircuit<
		E,
		NUM_DECIMAL_LIMBS,
		POWER_OF_TEN,
		NUM_NEIGHBOURS,
		INITIAL_SCORE,
		NUM_LIMBS,
		NUM_BITS,
		P,
		EC,
		S,
		H,
		R,
	> where
	E::Scalar: FieldExt,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<E::G1Affine>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	R: RoundParams<E::Scalar, HASHER_WIDTH>,
{
	/// Constructs a new ThresholdCircuit
	pub fn new<SN: SpongeHasher<E::Scalar>>(
		sets: &[E::Scalar], scores: &[E::Scalar], num_decomposed: &[E::Scalar],
		den_decomposed: &[E::Scalar], svk: Svk<E::G1Affine>,
		snarks: Vec<Snark<E, NUM_LIMBS, NUM_BITS, P, SN, EC>>, as_proof: Vec<u8>,
	) -> Self {
		let sets = sets.iter().map(|s| Value::known(*s)).collect();
		let scores = scores.iter().map(|s| Value::known(*s)).collect();
		let num_decomposed =
			(0..NUM_DECIMAL_LIMBS).map(|i| Value::known(num_decomposed[i])).collect();
		let den_decomposed =
			(0..NUM_DECIMAL_LIMBS).map(|i| Value::known(den_decomposed[i])).collect();

		let snarks = snarks.into_iter().map(UnassignedSnark::from).collect();
		let as_proof = Some(as_proof);

		Self {
			sets,
			scores,
			den_decomposed,
			num_decomposed,
			svk,
			snarks,
			as_proof,
			_p: PhantomData,
		}
	}
}

impl<
		E: MultiMillerLoop,
		const NUM_DECIMAL_LIMBS: usize,
		const POWER_OF_TEN: usize,
		const NUM_NEIGHBOURS: usize,
		const INITIAL_SCORE: u128,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		S,
		H,
		R,
	> Circuit<E::Scalar>
	for ThresholdCircuit<
		E,
		NUM_DECIMAL_LIMBS,
		POWER_OF_TEN,
		NUM_NEIGHBOURS,
		INITIAL_SCORE,
		NUM_LIMBS,
		NUM_BITS,
		P,
		EC,
		S,
		H,
		R,
	> where
	E::Scalar: FieldExt,
	<E::G1Affine as CurveAffine>::Base: FieldExt,
	P: RnsParams<<E::G1Affine as CurveAffine>::Base, E::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<E::G1Affine>,
	S: SpongeHasherChipset<E::Scalar>,
	H: SpongeHasher<E::Scalar>,
	R: RoundParams<E::Scalar, HASHER_WIDTH>,
{
	type Config = ThresholdCircuitConfig<E::Scalar, S>;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		let sets = (0..NUM_NEIGHBOURS).map(|_| Value::unknown()).collect();
		let scores = (0..NUM_NEIGHBOURS).map(|_| Value::unknown()).collect();
		let num_decomposed = (0..NUM_DECIMAL_LIMBS).map(|_| Value::unknown()).collect();
		let den_decomposed = (0..NUM_DECIMAL_LIMBS).map(|_| Value::unknown()).collect();

		let svk = self.svk;
		let snarks = self.snarks.iter().map(UnassignedSnark::without_witness).collect();
		let as_proof = None;

		Self {
			sets,
			scores,
			num_decomposed,
			den_decomposed,
			svk,
			snarks,
			as_proof,
			_p: PhantomData,
		}
	}

	fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let bits_2_num_selector = Bits2NumChip::configure(&common, meta);
		let n_shifted_selector = NShiftedChip::configure(&common, meta);
		let lt_eq = LessEqualConfig::new(main.clone(), bits_2_num_selector, n_shifted_selector);

		let sponge = S::configure(&common, meta);

		let integer_add_selector = IntegerAddChip::<
			<E::G1Affine as CurveAffine>::Base,
			E::Scalar,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::configure(&common, meta);
		let integer_sub_selector = IntegerSubChip::<
			<E::G1Affine as CurveAffine>::Base,
			E::Scalar,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::configure(&common, meta);
		let integer_mul_selector = IntegerMulChip::<
			<E::G1Affine as CurveAffine>::Base,
			E::Scalar,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::configure(&common, meta);
		let integer_div_selector = IntegerDivChip::<
			<E::G1Affine as CurveAffine>::Base,
			E::Scalar,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::configure(&common, meta);
		let ladder = EccUnreducedLadderConfig::new(
			integer_add_selector, integer_sub_selector, integer_mul_selector, integer_div_selector,
		);
		let integer_reduce_selector = IntegerReduceChip::<
			<E::G1Affine as CurveAffine>::Base,
			E::Scalar,
			NUM_LIMBS,
			NUM_BITS,
			P,
		>::configure(&common, meta);
		let add = EccAddConfig::new(
			integer_reduce_selector, integer_sub_selector, integer_mul_selector,
			integer_div_selector,
		);
		let double = EccDoubleConfig::new(
			integer_reduce_selector, integer_add_selector, integer_sub_selector,
			integer_mul_selector, integer_div_selector,
		);
		let table_select = EccTableSelectConfig::new(main.clone());
		let bits2num = Bits2NumChip::configure(&common, meta);
		let ecc_mul_scalar = EccMulConfig::new(ladder, add, double, table_select, bits2num);
		let ecc_add = EccAddConfig::new(
			integer_reduce_selector, integer_sub_selector, integer_mul_selector,
			integer_div_selector,
		);
		let ecc_double = EccDoubleConfig::new(
			integer_reduce_selector, integer_add_selector, integer_sub_selector,
			integer_mul_selector, integer_div_selector,
		);
		let aux = AuxConfig::new(ecc_double);
		let aggregator = AggregatorConfig::new(main.clone(), sponge, ecc_mul_scalar, ecc_add, aux);

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
		&self, config: Self::Config, mut layouter: impl Layouter<E::Scalar>,
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
					E::Scalar::from_u128(NUM_NEIGHBOURS as u128),
				)?;
				let init_score = ctx.assign_from_constant(
					config.common.advice[1],
					E::Scalar::from_u128(INITIAL_SCORE),
				)?;
				let max_limb_value = ctx.assign_from_constant(
					config.common.advice[2],
					E::Scalar::from_u128(10_u128).pow([POWER_OF_TEN as u64]),
				)?;
				let one = ctx.assign_from_constant(config.common.advice[5], E::Scalar::ONE)?;
				let zero = ctx.assign_from_constant(config.common.advice[6], E::Scalar::ZERO)?;

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
		// TODO: Use actual set and scores as PI for aggregator
		let aggregator = AggregatorChipset::<E, NUM_LIMBS, NUM_BITS, P, S, H, EC>::new(
			self.svk,
			self.snarks.clone(),
			self.as_proof.clone(),
		);
		let halo2_agg_limbs = aggregator.synthesize(
			&config.common,
			&config.aggregator,
			layouter.namespace(|| "aggregation"),
		)?;
		layouter.assign_region(
			|| "native_agg_limbs == halo2_agg_limbs",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..halo2_agg_limbs.len() {
					let native_limb = ctx.assign_from_instance(
						config.common.advice[0],
						config.common.instance,
						3 + i,
					)?;
					let halo2_limb =
						ctx.copy_assign(config.common.advice[1], halo2_agg_limbs[i].clone())?;
					ctx.constrain_equal(native_limb, halo2_limb)?;
					ctx.next();
				}

				Ok(())
			},
		)?;

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
			#[allow(clippy::redundant_clone)]
			let scale = max_limb_value.clone();

			let mut val = limbs[0].clone();
			for i in 1..limbs.len() {
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
			for i in 1..limbs.len() {
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
			dynamic_sets::{
				native::{Attestation, EigenTrustSet, SignedAttestation},
				EigenTrustSet as EigenTrustSetCircuit,
			},
			opinion::native::Opinion,
			threshold::native::Threshold,
			PoseidonHasher, PoseidonNativeHasher, PoseidonNativeSponge, SpongeHasher, HASHER_WIDTH,
		},
		ecdsa::native::{EcdsaKeypair, PublicKey},
		params::{
			ecc::{bn254::Bn254Params, secp256k1::Secp256k1Params},
			hasher::poseidon_bn254_5x5::Params,
			rns::{bn256::Bn256_4_68, secp256k1::Secp256k1_4_68},
		},
		utils::{big_to_fe, big_to_fe_rat, fe_to_big, generate_params, prove_and_verify},
		verifier::aggregator::native::NativeAggregator,
	};
	use halo2::{
		arithmetic::Field,
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr, G1Affine},
			ff::PrimeField,
			secp256k1::Secp256k1Affine,
		},
	};
	use num_rational::BigRational;
	use rand::thread_rng;

	type E = Bn256;
	type N = Fr;
	type HN = PoseidonNativeHasher;
	type SN = PoseidonNativeSponge;
	type H = PoseidonHasher;
	type S = SpongeHasher;
	type P = Bn256_4_68;
	type EC = Bn254Params;
	type R = Params;

	const DOMAIN: u128 = 42;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;

	type CSecp = Secp256k1Affine;
	type PSecp = Secp256k1_4_68;
	type ECSecp = Secp256k1Params;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		keypair: &EcdsaKeypair<CSecp, N, NUM_LIMBS, NUM_BITS, PSecp, ECSecp>, pks: &[N],
		scores: &[N],
	) -> Vec<Option<SignedAttestation<CSecp, N, NUM_LIMBS, NUM_BITS, PSecp>>> {
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
				let msg = big_to_fe(fe_to_big(attestation.hash::<HASHER_WIDTH, HN>()));
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
	) -> (
		(Vec<N>, Vec<N>, Vec<BigRational>),
		(
			Vec<Vec<Option<SignedAttestation<CSecp, N, NUM_LIMBS, NUM_BITS, PSecp>>>>,
			Vec<Option<PublicKey<CSecp, N, NUM_LIMBS, NUM_BITS, PSecp, ECSecp>>>,
			Vec<Fr>,
		),
	) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			CSecp,
			N,
			NUM_LIMBS,
			NUM_BITS,
			PSecp,
			ECSecp,
			HN,
			SN,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypairs: Vec<EcdsaKeypair<CSecp, _, NUM_LIMBS, NUM_BITS, _, _>> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| EcdsaKeypair::generate_keypair(rng)).collect();

		let pks: Vec<PublicKey<CSecp, _, NUM_LIMBS, NUM_BITS, _, _>> =
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
						Attestation::new(pks[j].to_address(), domain, ops[i][j], N::ZERO);

					let att_hash = attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>();
					let att_hash = big_to_fe(fe_to_big(att_hash));

					let signature = keypairs[i].sign(att_hash, rng);
					let signed_att = SignedAttestation::new(attestation, signature);

					attestations_i.push(signed_att);
				}
				attestations.push(attestations_i);

				let op: Opinion<
					NUM_NEIGHBOURS,
					CSecp,
					N,
					NUM_LIMBS,
					NUM_BITS,
					PSecp,
					ECSecp,
					HN,
					SN,
				> = Opinion::new(pks[i].clone(), attestations[i].clone(), domain);
				let (_, _, op_hash) = op.validate(set.clone());
				op_hashes.push(op_hash);
			}
			let mut sponge = SN::new();
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

		((pks_fr, s, s_ratios), (opt_att, opt_pks, public_inputs))
	}

	#[ignore = "threshold circuit test takes too long to run"]
	#[test]
	fn test_threshold_circuit() {
		// Test Threshold Circuit
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		const NUM_DECIMAL_LIMBS: usize = 2;
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

		let ((sets, scores, score_ratios), (opt_att, opt_pks, et_circuit_pi)) =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let target_idx = 2;

		let target_addr = sets[target_idx].clone();
		let score = scores[target_idx].clone();
		let score_ratio = score_ratios[target_idx].clone();
		let (num_decomposed, den_decomposed) =
			big_to_fe_rat::<N, NUM_DECIMAL_LIMBS, POWER_OF_TEN>(score_ratio.clone());
		let threshold = N::from_u128(1000_u128);

		let native_threshold: Threshold<
			N,
			NUM_DECIMAL_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
		> = Threshold::new(score, score_ratio, threshold);
		let native_threshold_check =
			if native_threshold.check_threshold() { N::ONE } else { N::ZERO };

		let pub_ins = vec![target_addr, threshold, native_threshold_check];

		// Prepare the Aggregator input
		let NativeAggregator { svk, snarks, instances, as_proof, .. } = {
			let rng = &mut thread_rng();
			let k = 20;
			let params = generate_params::<Bn256>(k);
			let et_circuit = EigenTrustSetCircuit::<
				NUM_NEIGHBOURS,
				NUM_ITERATIONS,
				INITIAL_SCORE,
				CSecp,
				N,
				NUM_LIMBS,
				NUM_BITS,
				PSecp,
				ECSecp,
				H,
				HN,
				S,
			>::new(opt_att, opt_pks, Fr::from_u128(DOMAIN));
			let et_circuit_instances: Vec<Vec<Fr>> = vec![et_circuit_pi];
			let snark_1 = Snark::<E, NUM_LIMBS, NUM_BITS, P, SN, EC>::new(
				&params, et_circuit, et_circuit_instances, rng,
			);

			let snarks = vec![snark_1];
			NativeAggregator::new(&params, snarks)
		};

		let pub_ins = [pub_ins, instances].concat();

		// Prepare the ThresholdCircuit
		let threshold_circuit: ThresholdCircuit<
			E,
			NUM_DECIMAL_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			S,
			PoseidonNativeSponge,
			R,
		> = ThresholdCircuit::new(
			&sets, &scores, &num_decomposed, &den_decomposed, svk, snarks, as_proof,
		);

		let k = 21;
		let prover = match MockProver::<N>::run(k, &threshold_circuit, vec![pub_ins]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[ignore = "threshold circuit test takes too long to run"]
	#[test]
	fn test_threshold_circuit_prod() {
		// Test Threshold Circuit production
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		const NUM_DECIMAL_LIMBS: usize = 2;
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

		let ((sets, scores, score_ratios), (opt_att, opt_pks, et_circuit_pi)) =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let target_idx = 2;

		let target_addr = sets[target_idx].clone();
		let score = scores[target_idx].clone();
		let score_ratio = score_ratios[target_idx].clone();
		let (num_decomposed, den_decomposed) =
			big_to_fe_rat::<N, NUM_DECIMAL_LIMBS, POWER_OF_TEN>(score_ratio.clone());
		let threshold = N::from_u128(1000_u128);

		let native_threshold: Threshold<
			N,
			NUM_DECIMAL_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
		> = Threshold::new(score, score_ratio, threshold);
		let native_threshold_check =
			if native_threshold.check_threshold() { N::ONE } else { N::ZERO };

		let pub_ins = vec![target_addr, threshold, native_threshold_check];

		// Prepare the Aggregator input
		let NativeAggregator { svk, snarks, instances, as_proof, .. } = {
			let rng = &mut thread_rng();
			let k = 20;
			let params = generate_params::<Bn256>(k);

			let et_circuit = EigenTrustSetCircuit::<
				NUM_NEIGHBOURS,
				NUM_ITERATIONS,
				INITIAL_SCORE,
				CSecp,
				N,
				NUM_LIMBS,
				NUM_BITS,
				PSecp,
				ECSecp,
				H,
				HN,
				S,
			>::new(opt_att, opt_pks, Fr::from_u128(DOMAIN));
			let et_circuit_instances: Vec<Vec<Fr>> = vec![et_circuit_pi];
			let snark_1 = Snark::new(&params, et_circuit, et_circuit_instances, rng);

			let snarks = vec![snark_1];
			NativeAggregator::new(&params, snarks)
		};

		let pub_ins = [pub_ins, instances].concat();

		let threshold_circuit: ThresholdCircuit<
			E,
			NUM_DECIMAL_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			S,
			PoseidonNativeSponge,
			R,
		> = ThresholdCircuit::new::<SN>(
			&sets, &scores, &num_decomposed, &den_decomposed, svk, snarks, as_proof,
		);

		let k = 21;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, threshold_circuit, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
