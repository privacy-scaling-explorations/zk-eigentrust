/// Native version of EigenTrustSet(ECDSA)
pub mod native;

use self::native::Attestation;
use super::opinion::{AssignedSignedAttestation, AttestationAssigner};
use super::opinion::{OpinionChipset, OpinionConfig};
use crate::circuits::opinion::UnassignedAttestation;
use crate::circuits::HASHER_WIDTH;
use crate::ecc::generic::native::EcPoint;
use crate::ecc::generic::UnassignedEcPoint;
use crate::ecc::{
	AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
	EccUnreducedLadderConfig,
};
use crate::ecdsa::native::{PublicKey, Signature};
use crate::ecdsa::{
	EcdsaAssigner, EcdsaAssignerConfig, EcdsaConfig, UnassignedPublicKey, UnassignedSignature,
};
use crate::gadgets::set::{SetChip, SetConfig};
use crate::integer::native::Integer;
use crate::integer::{
	IntegerAddChip, IntegerAssigner, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
	IntegerSubChip, LeftShiftersAssigner, UnassignedInteger,
};
use crate::params::ecc::EccParams;
use crate::params::rns::RnsParams;
use crate::UnassignedValue;
use crate::{
	gadgets::{
		bits2num::Bits2NumChip,
		main::{
			AddChipset, AndChipset, InverseChipset, IsEqualChipset, MainChip, MainConfig,
			MulChipset, OrChipset, SelectChipset, SubChipset,
		},
	},
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use crate::{FieldExt, HasherChipset, SpongeHasherChipset};
use halo2::halo2curves::CurveAffine;
use halo2::{
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;
use std::marker::PhantomData;

#[derive(Clone)]
/// The columns config for the EigenTrustSet circuit.
pub struct EigenTrustSetConfig<F: FieldExt, H, S>
where
	H: HasherChipset<F, HASHER_WIDTH>,
	S: SpongeHasherChipset<F, HASHER_WIDTH>,
{
	common: CommonConfig,
	main: MainConfig,
	hasher: H::Config,
	sponge: S::Config,
	ecdsa_assigner: EcdsaAssignerConfig,
	opinion: OpinionConfig<F, H, S>,
}

#[derive(Clone)]
/// Structure of the EigenTrustSet circuit
pub struct EigenTrustSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITER: usize,
	const INITIAL_SCORE: u128,
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
	H,
	SH,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, HASHER_WIDTH>,
	SH: SpongeHasherChipset<N, HASHER_WIDTH>,
{
	// Attestation
	attestations: Vec<Vec<UnassignedAttestation<N>>>,
	// Signature
	signatures: Vec<UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>>,
	// Public keys
	pks: Vec<UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>>,
	// Message hash
	msg_hash: Vec<Vec<UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>>,
	// Set
	set: Vec<Value<N>>,
	// Signature s inverse
	s_inv: Vec<UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
	/// Generator as EC point
	g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	// Phantom Data
	_p: PhantomData<(H, SH)>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		H,
		SH,
	> EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, C, N, NUM_LIMBS, NUM_BITS, P, EC, H, SH>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, HASHER_WIDTH>,
	SH: SpongeHasherChipset<N, HASHER_WIDTH>,
{
	/// Constructs a new EigenTrustSet circuit
	pub fn new(
		attestations: Vec<Vec<Attestation<N>>>,
		signatures: Vec<Signature<C, N, NUM_LIMBS, NUM_BITS, P>>,
		pks: Vec<PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>>,
		msg_hash: Vec<Vec<Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>>, set: Vec<N>,
		s_inv: Vec<Integer<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
		g_as_ecpoint: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		//Attestation values
		let attestations = attestations
			.into_iter()
			.map(|att| att.into_iter().map(|x| UnassignedAttestation::from(x)).collect_vec())
			.collect_vec();
		// Signature values
		let signatures = signatures.into_iter().map(UnassignedSignature::from).collect_vec();
		// Pubkey values
		let pks = pks.into_iter().map(|x| UnassignedPublicKey::new(x)).collect_vec();

		let msg_hash = msg_hash
			.iter()
			.map(|ints| ints.iter().map(|int| UnassignedInteger::from(int.clone())).collect_vec())
			.collect_vec();

		let set = set.iter().map(|x| Value::known(*x)).collect();
		let s_inv = s_inv.iter().map(|int| UnassignedInteger::from(int.clone())).collect_vec();
		let g_as_ecpoint = UnassignedEcPoint::from(g_as_ecpoint);

		Self {
			attestations,
			signatures,
			pks,
			msg_hash,
			set,
			s_inv,
			g_as_ecpoint,
			_p: PhantomData,
		}
	}
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		H,
		SH,
	> Circuit<N>
	for EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, C, N, NUM_LIMBS, NUM_BITS, P, EC, H, SH>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, HASHER_WIDTH>,
	SH: SpongeHasherChipset<N, HASHER_WIDTH>,
{
	type Config = EigenTrustSetConfig<N, H, SH>;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		let att = UnassignedAttestation::without_witnesses();
		let pk = UnassignedPublicKey::without_witnesses();
		let sig = UnassignedSignature::without_witnesses();

		Self {
			attestations: vec![vec![att; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			signatures: vec![sig; NUM_NEIGHBOURS],
			pks: vec![pk; NUM_NEIGHBOURS],
			msg_hash: vec![vec![UnassignedInteger::without_witnesses(); NUM_NEIGHBOURS]],
			set: vec![Value::unknown(); NUM_NEIGHBOURS],
			s_inv: vec![UnassignedInteger::without_witnesses(); NUM_NEIGHBOURS],
			g_as_ecpoint: UnassignedEcPoint::without_witnesses(),
			_p: PhantomData,
		}
	}

	fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));
		let bits2num_selector = Bits2NumChip::configure(&common, meta);
		let set_selector = SetChip::configure(&common, meta);
		let set = SetConfig::new(main.clone(), set_selector);

		let integer_reduce_selector =
			IntegerReduceChip::<C::Base, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let integer_add_selector =
			IntegerAddChip::<C::Base, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let integer_sub_selector =
			IntegerSubChip::<C::Base, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let integer_mul_selector =
			IntegerMulChip::<C::Base, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let integer_div_selector =
			IntegerDivChip::<C::Base, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let integer_mul_selector_secp_scalar =
			IntegerMulChip::<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
		let ecc_add = EccAddConfig::new(
			integer_reduce_selector, integer_sub_selector, integer_mul_selector,
			integer_div_selector,
		);

		let ecc_double = EccDoubleConfig::new(
			integer_reduce_selector, integer_add_selector, integer_sub_selector,
			integer_mul_selector, integer_div_selector,
		);

		let ecc_ladder = EccUnreducedLadderConfig::new(
			integer_add_selector, integer_sub_selector, integer_mul_selector, integer_div_selector,
		);

		let ecc_table_select = EccTableSelectConfig::new(main.clone());

		let ecc_mul_scalar = EccMulConfig::new(
			ecc_ladder,
			ecc_add,
			ecc_double.clone(),
			ecc_table_select,
			bits2num_selector,
		);

		let ecdsa = EcdsaConfig::new(ecc_mul_scalar, integer_mul_selector_secp_scalar);
		let aux = AuxConfig::new(ecc_double);
		let ecdsa_assigner = EcdsaAssignerConfig::new(aux, integer_mul_selector_secp_scalar);
		let hasher = H::configure(&common, meta);
		let sponge = SH::configure(&common, meta);
		let opinion = OpinionConfig::new(ecdsa, main.clone(), set, hasher.clone(), sponge.clone());

		EigenTrustSetConfig { common, main, hasher, sponge, ecdsa_assigner, opinion }
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<(), Error> {
		let (zero, init_score, total_score, passed_s, one, set) = layouter.assign_region(
			|| "assigner",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);

				let zero = ctx.assign_from_constant(config.common.advice[0], N::ZERO)?;
				let one = ctx.assign_from_constant(config.common.advice[1], N::ONE)?;

				let assigned_initial_score =
					ctx.assign_from_constant(config.common.advice[3], N::from_u128(INITIAL_SCORE))?;

				let assigned_total_score = ctx.assign_from_constant(
					config.common.advice[4],
					N::from_u128(INITIAL_SCORE * NUM_NEIGHBOURS as u128),
				)?;

				// Move to the next row
				ctx.next();

				let mut passed_s = Vec::new();
				for i in 0..NUM_NEIGHBOURS {
					let index = i % ADVICE;
					let ps = ctx.assign_from_instance(
						config.common.advice[index], config.common.instance, i,
					)?;
					passed_s.push(ps);
					if i == ADVICE - 1 {
						ctx.next();
					}
				}
				ctx.next();

				let mut assigned_set = Vec::new();
				for chunk in self.set.chunks(ADVICE) {
					for (i, chunk_i) in chunk.iter().enumerate() {
						let s = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
						assigned_set.push(s)
					}
					// Move to the next row
					ctx.next();
				}

				Ok((
					zero, assigned_initial_score, assigned_total_score, passed_s, one, assigned_set,
				))
			},
		)?;

		let mut assigned_attestation = Vec::new();
		for atts in &self.attestations {
			let mut att_vec = Vec::new();
			for att in atts {
				let att_assigner = AttestationAssigner::new(att.clone());
				let assigned_att = att_assigner.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "att_assigner"),
				)?;
				att_vec.push(assigned_att);
			}
			assigned_attestation.push(att_vec);
		}

		let mut ops = Vec::new();
		// signature verification
		for i in 0..NUM_NEIGHBOURS {
			let ecdsa_assigner_chip = EcdsaAssigner::new(
				self.pks[i].clone(),
				self.g_as_ecpoint.clone(),
				self.signatures[i].clone(),
				self.msg_hash[i][0].clone(),
				self.s_inv[i].clone(),
			);
			let ecdsa_assigner = ecdsa_assigner_chip.synthesize(
				&config.common,
				&config.ecdsa_assigner,
				layouter.namespace(|| "ecdsa assigner"),
			)?;

			let assigned_public_key = ecdsa_assigner.public_key;
			let assigned_signature = ecdsa_assigner.signature;
			let g_as_ecpoint = ecdsa_assigner.g_as_ecpoint;
			let aux = ecdsa_assigner.auxes;

			let lshift: LeftShiftersAssigner<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P> =
				LeftShiftersAssigner::default();
			let left_shifters = lshift.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "lshift assigner"),
			)?;

			let mut assigned_signed_att = Vec::new();
			let mut assigned_msg_hash = Vec::new();
			let mut assigned_s_inv = Vec::new();

			assigned_msg_hash.push(ecdsa_assigner.msg_hash);
			assigned_s_inv.push(ecdsa_assigner.s_inv);

			// Assigning first iteration to catch s_inv and msg_hash
			assigned_signed_att.push(AssignedSignedAttestation::new(
				assigned_attestation[i][0].clone(),
				assigned_signature.clone(),
			));
			for j in 1..NUM_NEIGHBOURS {
				assigned_signed_att.push(AssignedSignedAttestation::new(
					assigned_attestation[i][j].clone(),
					assigned_signature.clone(),
				));

				let assign_msg_hash = IntegerAssigner::new(self.msg_hash[i][j].clone());
				let msg_hash = assign_msg_hash.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "assign msg_hash_i"),
				)?;
				assigned_msg_hash.push(msg_hash);

				let assign_s_inv = IntegerAssigner::new(self.msg_hash[i][j].clone());
				let s_inv = assign_s_inv.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "assign s_inv"),
				)?;
				assigned_s_inv.push(s_inv);
			}

			let opinion: OpinionChipset<NUM_NEIGHBOURS, C, N, NUM_LIMBS, NUM_BITS, P, EC, H, SH> =
				OpinionChipset::new(
					assigned_signed_att,
					assigned_public_key,
					set.clone(),
					assigned_msg_hash,
					g_as_ecpoint,
					assigned_s_inv,
					aux,
					left_shifters,
				);

			let (opinions, _) = opinion.synthesize(
				&config.common,
				&config.opinion,
				layouter.namespace(|| "opinion"),
			)?;
			ops.push(opinions);
		}

		// filter peers' ops
		let ops = {
			let mut filtered_ops = Vec::new();

			for i in 0..NUM_NEIGHBOURS {
				let addr_i = set[i].clone();
				let mut ops_i = Vec::new();

				// Update the opinion array - pairs of (key, score)
				for j in 0..NUM_NEIGHBOURS {
					let addr_j = set[j].clone();

					// Condition: addr_j != Address::zero()
					let equal_chip = IsEqualChipset::new(addr_j.clone(), zero.clone());
					let is_default_addr = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_addr_j == default_addr"),
					)?;

					// Condition: set_addr_j == addr_i
					let equal_chip = IsEqualChipset::new(addr_j.clone(), addr_i.clone());
					let is_addr_i = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "addr_j == addr_i"),
					)?;

					// Conditions for nullifying the score
					// 1. set_addr_j == 0 (null or default)
					// 2. set_addr_j == addr_i
					let or_chip = OrChipset::new(is_addr_i.clone(), is_default_addr);
					let cond = or_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_addr_i || is_addr_j_null"),
					)?;

					let select_chip = SelectChipset::new(cond, zero.clone(), ops[i][j].clone());
					let new_ops_i_j = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "filtered op score"),
					)?;
					ops_i.push(new_ops_i_j);
				}

				// Distribute the scores
				let mut op_score_sum = zero.clone();
				for j in 0..NUM_NEIGHBOURS {
					let add_chip = AddChipset::new(op_score_sum.clone(), ops_i[j].clone());
					op_score_sum = add_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_score_sum"),
					)?;
				}

				let equal_chip = IsEqualChipset::new(op_score_sum, zero.clone());
				let is_sum_zero = equal_chip.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "op_score_sum == 0"),
				)?;

				for j in 0..NUM_NEIGHBOURS {
					let addr_j = set[j].clone();
					// Condition 1. addr_j != addr_i
					let equal_chip = IsEqualChipset::new(addr_j.clone(), addr_i.clone());
					let is_add_i = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_pk_j_x == pk_i_x"),
					)?;
					let sub = SubChipset::new(one.clone(), is_add_i);
					let is_not_add_i = sub.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| " 1 - is_add_i"),
					)?;

					// Condition 2. addr_j != Address::zero()
					let equal_chip = IsEqualChipset::new(addr_j.clone(), zero.clone());
					let is_default_addr = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_addr_j == default_addr"),
					)?;
					let sub = SubChipset::new(one.clone(), is_default_addr);
					let is_not_default_addr = sub.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| " 1 - is_add_i"),
					)?;

					// Conditions for distributing the score
					// 1. pk_j != pk_i
					// 2. pk_j != PublicKey::default()
					// 3. op_score_sum == 0
					let and_chip = AndChipset::new(is_not_add_i, is_not_default_addr);
					let cond = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_not_add_i && is_not_null"),
					)?;
					let and_chip = AndChipset::new(cond, is_sum_zero.clone());
					let cond = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_not_add_i && is_not_null"),
					)?;
					let select_chip = SelectChipset::new(cond, one.clone(), ops_i[j].clone());
					ops_i[j] = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "filtered op score"),
					)?;
				}

				// Add to "filtered_ops"
				filtered_ops.push(ops_i);
			}

			filtered_ops
		};

		// "Normalization"
		let ops = {
			let mut normalized_ops = Vec::new();
			for i in 0..NUM_NEIGHBOURS {
				let mut ops_i = Vec::new();

				// Compute the sum of scores
				let mut op_score_sum = zero.clone();
				for j in 0..NUM_NEIGHBOURS {
					let add_chip = AddChipset::new(op_score_sum.clone(), ops[i][j].clone());
					op_score_sum = add_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_score_sum"),
					)?;
				}

				// Compute the normalized score
				//
				// Note: Here, there is no need to check if `op_score_sum` is zero.
				//       If `op_score_sum` is zero, it means all of opinion scores are zero.
				//		 Hence, the normalized score would be simply zero.
				let invert_chip = InverseChipset::new(op_score_sum);
				let inverted_sum = invert_chip.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "invert_sum"),
				)?;

				for j in 0..NUM_NEIGHBOURS {
					let mul_chip = MulChipset::new(ops[i][j].clone(), inverted_sum.clone());
					let normalized_op = mul_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op * inverted_sum"),
					)?;
					ops_i.push(normalized_op);
				}

				// Add to "normalized_ops"
				normalized_ops.push(ops_i);
			}

			normalized_ops
		};

		// Compute the EigenTrust scores
		let mut s = vec![init_score; NUM_NEIGHBOURS];
		for _ in 0..NUM_ITER {
			let mut sop = Vec::new();
			for i in 0..NUM_NEIGHBOURS {
				let mut sop_i = Vec::new();
				for j in 0..NUM_NEIGHBOURS {
					let mul_chip = MulChipset::new(ops[i][j].clone(), s[i].clone());
					let res = mul_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_mul"),
					)?;
					sop_i.push(res);
				}
				sop.push(sop_i);
			}

			let mut new_s = vec![zero.clone(); NUM_NEIGHBOURS];
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					let add_chip = AddChipset::new(new_s[i].clone(), ops[i][j].clone());
					new_s[i] = add_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_add"),
					)?;
				}
			}

			s = new_s;
		}

		// Constrain the final scores
		layouter.assign_region(
			|| "passed_s == s",
			|region: Region<'_, N>| {
				let ctx = &mut RegionCtx::new(region, 0);
				for i in 0..NUM_NEIGHBOURS {
					let passed_s = ctx.copy_assign(config.common.advice[0], passed_s[i].clone())?;
					let s = ctx.copy_assign(config.common.advice[1], s[i].clone())?;
					ctx.constrain_equal(passed_s, s)?;
					ctx.next();
				}
				Ok(())
			},
		)?;

		// Constrain the total reputation in the set
		let mut sum = zero;
		for i in 0..NUM_NEIGHBOURS {
			let add_chipset = AddChipset::new(sum.clone(), passed_s[i].clone());
			sum = add_chipset.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "s_sum"),
			)?;
		}
		layouter.assign_region(
			|| "s_sum == total_score",
			|region: Region<'_, N>| {
				let ctx = &mut RegionCtx::new(region, 0);
				let sum = ctx.copy_assign(config.common.advice[0], sum.clone())?;
				let total_score = ctx.copy_assign(config.common.advice[1], total_score.clone())?;
				ctx.constrain_equal(sum, total_score)?;
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		circuits::{
			dynamic_sets::native::SignedAttestation, opinion::native::Opinion,
			PoseidonNativeHasher, PoseidonNativeSponge,
		},
		ecdsa::native::EcdsaKeypair,
		params::{
			ecc::secp256k1::Secp256k1Params, hasher::poseidon_bn254_5x5::Params,
			rns::secp256k1::Secp256k1_4_68,
		},
		poseidon::{sponge::StatefulSpongeChipset, PoseidonChipset},
		utils::{big_to_fe, fe_to_big, generate_params, prove_and_verify},
	};
	use halo2::{
		arithmetic::Field,
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			ff::PrimeField,
			group::Curve,
			secp256k1::{Fq, Secp256k1, Secp256k1Affine},
		},
	};
	use rand::thread_rng;

	const NUM_NEIGHBOURS: usize = 5;
	const NUM_ITERATIONS: usize = 20;
	const INITIAL_SCORE: u128 = 1000;
	const DOMAIN: u128 = 42;

	type C = Secp256k1Affine;
	type WN = Fq;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;
	type H = PoseidonChipset<N, HASHER_WIDTH, Params>;
	type SH = StatefulSpongeChipset<N, HASHER_WIDTH, Params>;
	type HN = PoseidonNativeHasher;
	type SHN = PoseidonNativeSponge;

	#[ignore = "Currently not working"]
	#[test]
	fn test_closed_graph_circuit() {
		let ops: Vec<Vec<N>> = vec![
			vec![0, 200, 300, 500, 0],
			vec![100, 0, 100, 100, 700],
			vec![400, 100, 0, 200, 300],
			vec![100, 100, 700, 0, 100],
			vec![300, 100, 400, 200, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| N::from_u128(x)).collect())
		.collect();

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);
		let rng = &mut thread_rng();
		let sks = [(); NUM_NEIGHBOURS].map(|_| WN::random(rng.clone()));
		let keypairs = sks.clone().map(|x| EcdsaKeypair::from_private_key(x));
		let pub_keys = keypairs.clone().map(|kp| kp.public_key);
		let domain = N::from_u128(DOMAIN);

		let (res, attestations, signatures, s_inv, set, msg_hash) = {
			let mut et = native::EigenTrustSet::<
				NUM_NEIGHBOURS,
				NUM_ITERATIONS,
				INITIAL_SCORE,
				C,
				N,
				NUM_LIMBS,
				NUM_BITS,
				P,
				EC,
				HN,
				SHN,
			>::new(domain);

			let mut signatures = Vec::new();
			let mut attestations = Vec::new();
			let mut set = Vec::new();
			let mut msg_hash = Vec::new();
			let mut s_inv = Vec::new();

			for i in 0..NUM_NEIGHBOURS {
				et.add_member(pub_keys[i].clone().to_address());

				let mut attestations_option = Vec::new();
				let mut msg_hash_i = Vec::new();
				// Attestation to the other peers
				for j in 0..NUM_NEIGHBOURS {
					let attestation =
						Attestation::new(pub_keys[j].to_address(), Fr::ZERO, ops[i][j], Fr::ZERO);
					set.push(attestation.about.clone());

					let att_hasher: Fq = big_to_fe(fe_to_big(
						attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>(),
					));

					let signature = keypairs[i].sign(att_hasher.clone(), rng);
					let s_inv_fq = big_to_fe::<Fq>(signature.s.value()).invert().unwrap();

					msg_hash_i.push(Integer::from_w(att_hasher));
					s_inv.push(Integer::from_w(s_inv_fq));
					signatures.push(signature.clone());
					attestations_option.push(Some(SignedAttestation::new(attestation, signature)));
				}
				msg_hash.push(msg_hash_i);

				let default_att = SignedAttestation::default();
				let attestations_unwrapped = attestations_option
					.iter()
					.map(|x| x.clone().unwrap_or(default_att.clone()))
					.collect_vec();
				attestations.push(
					attestations_unwrapped.iter().map(|x| x.attestation.clone()).collect_vec(),
				);

				let op: Opinion<NUM_NEIGHBOURS, C, N, NUM_LIMBS, NUM_BITS, P, EC, HN, SHN> =
					Opinion::new(pub_keys[i].clone(), attestations_unwrapped.clone(), domain);
				let _ = op.validate(set.clone());

				et.update_op(pub_keys[i].clone(), attestations_option);
			}
			let s = et.converge();

			(s, attestations, signatures, s_inv, set, msg_hash)
		};

		let et = EigenTrustSet::<
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
		>::new(
			attestations,
			signatures,
			pub_keys.to_vec(),
			msg_hash,
			set,
			s_inv,
			g_as_ecpoint,
		);

		let k = 20;
		let prover = match MockProver::<N>::run(k, &et, vec![res.to_vec()]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[ignore = "Currently not working"]
	#[test]
	fn test_closed_graph_circut_prod() {
		let ops: Vec<Vec<N>> = vec![
			vec![0, 200, 300, 500, 0],
			vec![100, 0, 100, 100, 700],
			vec![400, 100, 0, 200, 300],
			vec![100, 100, 700, 0, 100],
			vec![300, 100, 400, 200, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| N::from_u128(x)).collect())
		.collect();

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);
		let rng = &mut thread_rng();
		let sks = [(); NUM_NEIGHBOURS].map(|_| WN::random(rng.clone()));
		let keypairs = sks.clone().map(|x| EcdsaKeypair::from_private_key(x));
		let pub_keys = keypairs.clone().map(|kp| kp.public_key).to_vec();
		let domain = N::from_u128(DOMAIN);

		let (res, attestations, signatures, s_inv, set, msg_hash) = {
			let mut et = native::EigenTrustSet::<
				NUM_NEIGHBOURS,
				NUM_ITERATIONS,
				INITIAL_SCORE,
				C,
				N,
				NUM_LIMBS,
				NUM_BITS,
				P,
				EC,
				HN,
				SHN,
			>::new(domain);

			let mut signatures = Vec::new();
			let mut attestations = Vec::new();
			let mut set = Vec::new();
			let mut msg_hash = Vec::new();
			let mut s_inv = Vec::new();

			for i in 0..NUM_NEIGHBOURS {
				et.add_member(pub_keys[i].clone().to_address());

				let mut attestations_option = Vec::new();
				let mut msg_hash_i = Vec::new();
				// Attestation to the other peers
				for j in 0..NUM_NEIGHBOURS {
					let attestation =
						Attestation::new(pub_keys[j].to_address(), Fr::ZERO, ops[i][j], Fr::ZERO);
					set.push(attestation.about.clone());

					let att_hasher: Fq = big_to_fe(fe_to_big(
						attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>(),
					));

					let signature = keypairs[i].sign(att_hasher.clone(), rng);
					let s_inv_fq = big_to_fe::<Fq>(signature.s.value()).invert().unwrap();

					msg_hash_i.push(Integer::from_w(att_hasher));
					s_inv.push(Integer::from_w(s_inv_fq));
					signatures.push(signature.clone());
					attestations_option.push(Some(SignedAttestation::new(attestation, signature)));
				}
				msg_hash.push(msg_hash_i);

				let default_att = SignedAttestation::default();
				let attestations_unwrapped = attestations_option
					.iter()
					.map(|x| x.clone().unwrap_or(default_att.clone()))
					.collect_vec();
				attestations.push(
					attestations_unwrapped.iter().map(|x| x.attestation.clone()).collect_vec(),
				);

				let op: Opinion<NUM_NEIGHBOURS, C, N, NUM_LIMBS, NUM_BITS, P, EC, HN, SHN> =
					Opinion::new(pub_keys[i].clone(), attestations_unwrapped.clone(), domain);
				let _ = op.validate(set.clone());

				et.update_op(pub_keys[i].clone(), attestations_option);
			}
			let s = et.converge();

			(s, attestations, signatures, s_inv, set, msg_hash)
		};

		let et = EigenTrustSet::<
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
		>::new(
			attestations, signatures, pub_keys, msg_hash, set, s_inv, g_as_ecpoint,
		);

		let k = 14;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, et, &[&res], rng).unwrap();
		assert!(res);
	}
}
