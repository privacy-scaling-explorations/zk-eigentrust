/// Native version of EigenTrustSet(ECDSA)
pub mod native;

use super::opinion::{AssignedAttestation, AssignedSignedAttestation};
use super::opinion::{OpinionChipset, OpinionConfig, WIDTH};
use crate::circuits::opinion::UnassignedAttestation;
use crate::ecc::generic::AssignedAux;
use crate::ecc::generic::AssignedEcPoint;
use crate::ecc::generic::PointAssigner;
use crate::ecc::{
	AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
	EccUnreducedLadderConfig,
};
use crate::ecdsa::native::{PublicKey, Signature};
use crate::ecdsa::{
	AssignedPublicKey, AssignedSignature, EcdsaConfig, UnassignedPublicKey, UnassignedSignature,
};
use crate::gadgets::set::{SetChip, SetConfig};
use crate::integer::{
	AssignedInteger, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
	IntegerSubChip,
};
use crate::params::ecc::EccParams;
use crate::params::hasher::poseidon_bn254_5x5::Params;
use crate::params::rns::RnsParams;
use crate::poseidon::{FullRoundChip, PartialRoundChip, PoseidonConfig};
use crate::UnassignedValue;
use crate::{
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		main::{
			AddChipset, AndChipset, InverseChipset, IsEqualChipset, MainChip, MainConfig,
			MulChipset, OrChipset, SelectChipset, SubChipset,
		},
	},
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use crate::{FieldExt, HasherChipset, SpongeHasherChipset};
use halo2::circuit::AssignedCell;
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
	H: HasherChipset<F, WIDTH>,
	S: SpongeHasherChipset<F, WIDTH>,
{
	common: CommonConfig,
	main: MainConfig,
	sponge: S::Config,
	hasher: H::Config,
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
	H,
	S,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N, WIDTH>,
{
	// Attestation
	attestation: Vec<Vec<UnassignedAttestation<N>>>,
	// Public keys
	pks: Vec<UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>>,
	// Signature
	signatures: Vec<UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>>,
	// Opinions
	op_pk_x: Vec<Vec<Value<N>>>,
	op_pk_y: Vec<Vec<Value<N>>>,
	ops: Vec<Vec<Value<N>>>,
	// Set
	set: Vec<Value<N>>,
	/// Generator as EC point
	g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	/// Aux for to_add and to_sub
	aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	/// Left shifters for composing integers
	left_shifters: [AssignedCell<N, N>; NUM_LIMBS],
	// Phantom Data
	_p: PhantomData<(H, S)>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		H,
		S,
		P,
		EC,
	> EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, C, N, NUM_LIMBS, NUM_BITS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N, WIDTH>,
{
	/// Constructs a new EigenTrustSet circuit
	pub fn new(
		attestation: Vec<Vec<UnassignedAttestation<N>>>,
		pks: Vec<PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>>,
		signatures: Vec<Signature<C, N, NUM_LIMBS, NUM_BITS, P>>,
		op_pks: Vec<Vec<PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>>>, ops: Vec<Vec<N>>,
		set: Vec<N>, g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		left_shifters: [AssignedCell<N, N>; NUM_LIMBS],
	) -> Self {
		// Attestation values
		// TODO: Uncomment when AttestationFr is not hardcoded
		//let attestation = attestation
		//	.into_iter()
		//	.map(|att| att.into_iter().map(|x| UnassignedAttestation::from(x)).collect_vec())
		//	.collect_vec();
		// Pubkey values
		let pks = pks.into_iter().map(|x| UnassignedPublicKey::new(x)).collect_vec();

		// Signature values
		let signatures = signatures.into_iter().map(UnassignedSignature::from).collect_vec();

		// Opinions
		let op_pks = op_pks
			.into_iter()
			.map(|pks| pks.into_iter().map(|x| UnassignedPublicKey::new(x)).collect_vec())
			.collect_vec();
		let op_pk_x = op_pks.iter().map(|pks| pks.iter().map(|pk| pk.0.x.val).collect()).collect();
		let op_pk_y = op_pks.iter().map(|pks| pks.iter().map(|pk| pk.0.y.val).collect()).collect();
		let ops = ops.iter().map(|vals| vals.iter().map(|x| Value::known(*x)).collect()).collect();

		let set = set.iter().map(|x| Value::known(*x)).collect();

		Self {
			attestation,
			pks,
			signatures,
			op_pk_x,
			op_pk_y,
			ops,
			set,
			g_as_ecpoint,
			aux,
			left_shifters,
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
		H,
		S,
		P,
		EC,
	> Circuit<N>
	for EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, C, N, NUM_LIMBS, NUM_BITS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N, WIDTH>,
{
	type Config = EigenTrustSetConfig<N, H, S>;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		let pk: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC> =
			UnassignedPublicKey::without_witnesses();
		let sig: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P> =
			UnassignedSignature::without_witnesses();
		let op_pk: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC> =
			UnassignedPublicKey::without_witnesses();
		Self {
			pks: vec![pk; NUM_NEIGHBOURS],
			signatures: vec![sig; NUM_NEIGHBOURS],
			op_pk_x: vec![vec![op_pk.0.x.val; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			op_pk_y: vec![vec![op_pk.0.y.val; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			ops: vec![vec![Value::unknown(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			// TODO: Find better way for g_as_ec, aux and lshifters
			attestation: vec![vec![UnassignedAttestation::without_witnesses()]],
			set: self.set,
			g_as_ecpoint: self.g_as_ecpoint,
			aux: self.aux,
			left_shifters: self.left_shifters,
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
			ecc_ladder.clone(),
			ecc_add.clone(),
			ecc_double.clone(),
			ecc_table_select,
			bits2num_selector.clone(),
		);

		let ecdsa = EcdsaConfig::new(ecc_mul_scalar, integer_mul_selector_secp_scalar);

		let aux = AuxConfig::new(ecc_double);

		let fr_selector = FullRoundChip::<_, WIDTH, Params>::configure(&common, meta);
		let pr_selector = PartialRoundChip::<_, WIDTH, Params>::configure(&common, meta);
		let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
		let hasher = H::configure(fr_selector, pr_selector);
		let absorb_selector = AbsorbChip::<_, WIDTH>::configure(&common, meta);
		let sponge = S::configure(poseidon.clone(), absorb_selector);

		let opinion = OpinionConfig::new(ecdsa, main, set, hasher, sponge);

		EigenTrustSetConfig { common, main, sponge, hasher, opinion }
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<(), Error> {
		let (
			zero,
			attestation,
			pk_x,
			pk_y,
			r,
			s,
			ops,
			init_score,
			total_score,
			passed_s,
			one,
			default_pk_x,
			default_pk_y,
			op_pk_x,
			op_pk_y,
			set,
		) = layouter.assign_region(
			|| "temp",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);

				let zero = ctx.assign_from_constant(config.common.advice[0], N::ZERO)?;

				let assigned_initial_score =
					ctx.assign_from_constant(config.common.advice[2], N::from_u128(INITIAL_SCORE))?;

				let assigned_total_score = ctx.assign_from_constant(
					config.common.advice[3],
					N::from_u128(INITIAL_SCORE * NUM_NEIGHBOURS as u128),
				)?;

				// Move to the next row
				ctx.next();

				let mut assigned_attestation = Vec::new();
				for neighbour_ops in &self.attestation {
					let mut assigned_attestation_i = Vec::new();
					for chunk in neighbour_ops.chunks(ADVICE) {
						for (i, chunk_i) in chunk.iter().enumerate() {
							let about =
								ctx.assign_advice(config.common.advice[i], chunk_i.about)?;
							let domain =
								ctx.assign_advice(config.common.advice[i], chunk_i.domain)?;
							let value =
								ctx.assign_advice(config.common.advice[i], chunk_i.value)?;
							let message =
								ctx.assign_advice(config.common.advice[i], chunk_i.about)?;

							let s = AssignedAttestation::new(about, domain, value, message);

							assigned_attestation_i.push(s)
						}
						// Move to the next row
						ctx.next();
					}
					assigned_attestation.push(assigned_attestation_i);
				}

				let unassigned_pk_x = self.pks.iter().map(|pk| pk.0.x.val).collect_vec();
				let mut assigned_pk_x = Vec::new();
				for chunk in unassigned_pk_x.chunks(ADVICE) {
					for (i, chunk_i) in chunk.iter().enumerate() {
						let pk_x = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
						assigned_pk_x.push(pk_x)
					}
					// Move to the next row
					ctx.next();
				}

				let unassigned_pk_y = self.pks.iter().map(|pk| pk.0.x.val).collect_vec();
				let mut assigned_pk_y = Vec::new();
				for chunk in unassigned_pk_y.chunks(ADVICE) {
					for (i, chunk_i) in chunk.iter().enumerate() {
						let pk_y = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
						assigned_pk_y.push(pk_y)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_r = Vec::new();
				for chunk in self.signatures.chunks(ADVICE) {
					for (i, chunk_i) in chunk.iter().enumerate() {
						let mut assigned_limbs = [(); NUM_LIMBS].map(|_| None);
						for j in 0..NUM_LIMBS {
							let r =
								ctx.assign_advice(config.common.advice[j], chunk_i.r.limbs[j])?;
							assigned_limbs[j] = Some(r);
						}
						assigned_r.push(assigned_limbs.map(|x| x.unwrap()))
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_s = Vec::new();
				for chunk in self.signatures.chunks(ADVICE) {
					for (i, chunk_i) in chunk.iter().enumerate() {
						let mut assigned_limbs = [(); NUM_LIMBS].map(|_| None);
						for j in 0..NUM_LIMBS {
							let s =
								ctx.assign_advice(config.common.advice[j], chunk_i.s.limbs[j])?;
							assigned_limbs[j] = Some(s);
						}
						assigned_s.push(assigned_limbs.map(|x| x.unwrap()))
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_ops = Vec::new();
				for neighbour_ops in &self.ops {
					let mut assigned_neighbour_op = Vec::new();
					for chunk in neighbour_ops.chunks(ADVICE) {
						for (i, chunk_i) in chunk.iter().enumerate() {
							let s = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
							assigned_neighbour_op.push(s)
						}
						// Move to the next row
						ctx.next();
					}
					assigned_ops.push(assigned_neighbour_op);
				}

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

				let one = ctx.assign_from_constant(config.common.advice[0], N::ONE)?;

				let default_pk_x = ctx.assign_advice(
					config.common.advice[1],
					Value::known(P::compose(PublicKey::default().0.x.limbs)),
				)?;

				let default_pk_y = ctx.assign_advice(
					config.common.advice[2],
					Value::known(P::compose(PublicKey::default().0.y.limbs)),
				)?;
				ctx.next();

				let mut assigned_op_pk_x = Vec::new();
				for neighbour_pk_x in &self.op_pk_x {
					let mut assigned_neighbour_pk_x = Vec::new();
					for chunk in neighbour_pk_x.chunks(ADVICE) {
						for (i, chunk_i) in chunk.iter().enumerate() {
							let x = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
							assigned_neighbour_pk_x.push(x);
						}
						// Move to the next row
						ctx.next();
					}
					assigned_op_pk_x.push(assigned_neighbour_pk_x);
				}

				let mut assigned_op_pk_y = Vec::new();
				for neighbour_pk_y in &self.op_pk_y {
					let mut assigned_neighbour_pk_y = Vec::new();
					for chunk in neighbour_pk_y.chunks(ADVICE) {
						for (i, chunk_i) in chunk.iter().enumerate() {
							let y = ctx.assign_advice(config.common.advice[i], *chunk_i)?;
							assigned_neighbour_pk_y.push(y);
						}
						// Move to the next row
						ctx.next();
					}
					assigned_op_pk_y.push(assigned_neighbour_pk_y);
				}

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
					zero, assigned_attestation, assigned_pk_x, assigned_pk_y, assigned_r,
					assigned_s, assigned_ops, assigned_initial_score, assigned_total_score,
					passed_s, one, default_pk_x, default_pk_y, assigned_op_pk_x, assigned_op_pk_y,
					assigned_set,
				))
			},
		)?;

		// signature verification
		let zero_state = [zero.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone()];
		let mut pk_sponge = S::init(&config.common, layouter.namespace(|| "sponge"))?;
		pk_sponge.update(&pk_x);
		pk_sponge.update(&pk_y);
		let pks_hash = pk_sponge.squeeze(
			&config.common,
			&config.sponge,
			layouter.namespace(|| "pks_sponge"),
		)?;

		for i in 0..NUM_NEIGHBOURS {
			let mut scores_sponge = S::init(&config.common, layouter.namespace(|| "sponge"))?;
			scores_sponge.update(&ops[i]);
			let scores_message_hash = scores_sponge.squeeze(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "scores_sponge"),
			)?;
			let message_hash_input = [
				pks_hash.clone(),
				scores_message_hash.clone(),
				zero.clone(),
				zero.clone(),
				zero.clone(),
			];
			let hasher = H::new(message_hash_input);
			let res = hasher.finalize(
				&config.common,
				&config.hasher,
				layouter.namespace(|| "message_hash"),
			)?;

			let assigned_public_key = PointAssigner::new(self.pks[i].0);
			let assigned_public_key_ec = assigned_public_key.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "public_key_assign_ec"),
			)?;
			let assigned_public_key = AssignedPublicKey::new(assigned_public_key_ec);

			let assigned_r_integer = AssignedInteger::new(self.signatures[i].r.integer, r[i]);
			let assigned_s_integer = AssignedInteger::new(self.signatures[i].s.integer, s[i]);
			let assigned_signature = AssignedSignature::new(assigned_r_integer, assigned_s_integer);
			let mut assigned_signed_att = Vec::new();

			for j in 0..NUM_NEIGHBOURS {
				assigned_signed_att.push(AssignedSignedAttestation::new(
					attestation[i][j], assigned_signature,
				));
			}

			let opinion = OpinionChipset::new(
				assigned_signed_att, assigned_public_key, set, msg_hash, self.g_as_ecpoint, s_inv,
				self.aux, self.left_shifters,
			);
		}

		// filter peers' ops
		let ops = {
			let mut filtered_ops = Vec::new();

			for i in 0..NUM_NEIGHBOURS {
				let pk_i_x = pk_x[i].clone();
				let pk_i_y = pk_y[i].clone();

				let mut ops_i = Vec::new();

				let mut op_pk_x_i = Vec::new();
				let mut op_pk_y_i = Vec::new();

				// Update the opinion array - pairs of (key, score)
				for j in 0..NUM_NEIGHBOURS {
					let set_pk_j_x = pk_x[j].clone();
					let set_pk_j_y = pk_y[j].clone();
					let op_pk_j_x = op_pk_x[i][j].clone();
					let op_pk_j_y = op_pk_y[i][j].clone();

					// Condition: set_pk_j != op_pk_j
					let equal_chip = IsEqualChipset::new(set_pk_j_x.clone(), op_pk_j_x.clone());
					let is_same_pk_j_x = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_x == op_pk_j_x"),
					)?;
					let equal_chip = IsEqualChipset::new(set_pk_j_y.clone(), op_pk_j_y.clone());
					let is_same_pk_j_y = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_y == op_pk_j_y"),
					)?;
					let and_chip = AndChipset::new(is_same_pk_j_x, is_same_pk_j_y);
					let is_same_pk_j = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j == op_pk_j"),
					)?;
					let sub_chip = SubChipset::new(one.clone(), is_same_pk_j);
					let is_diff_pk_j = sub_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j != op_pk_j"),
					)?;

					// Condition: op_pk_j != PublicKey::default()
					let equal_chip = IsEqualChipset::new(set_pk_j_x.clone(), default_pk_x.clone());
					let is_default_pk_x = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_x == default_pk_x"),
					)?;
					let equal_chip = IsEqualChipset::new(set_pk_j_y.clone(), default_pk_y.clone());
					let is_default_pk_y = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_y == default_pk_y"),
					)?;
					let and_chip = AndChipset::new(is_default_pk_x, is_default_pk_y);
					let is_pk_j_null = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j == default_pk"),
					)?;

					// Condition: set_pk_j == pk_i
					let equal_chip = IsEqualChipset::new(set_pk_j_x.clone(), pk_i_x.clone());
					let is_pk_i_x = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_x == pk_i_x"),
					)?;
					let equal_chip = IsEqualChipset::new(set_pk_j_y.clone(), pk_i_y.clone());
					let is_pk_i_y = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j_y == pk_i_y"),
					)?;
					let and_chip = AndChipset::new(is_pk_i_x, is_pk_i_y);
					let is_pk_i = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "set_pk_j == pk_i"),
					)?;

					// Conditions for nullifying the score
					// 1. set_pk_j != op_pk_j
					// 2. set_pk_j == 0 (null or default)
					// 3. set_pk_j == pk_i
					let or_chip = OrChipset::new(is_diff_pk_j.clone(), is_pk_j_null);
					let cond = or_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_diff_pk_j || is_pk_j_null"),
					)?;
					let or_chip = OrChipset::new(cond, is_pk_i);
					let cond = or_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_diff_pk_j || is_pk_j_null || is_pk_i"),
					)?;

					let select_chip = SelectChipset::new(cond, zero.clone(), ops[i][j].clone());
					let new_ops_i_j = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "filtered op score"),
					)?;
					ops_i.push(new_ops_i_j);

					// Condition for correcting the pk
					// 1. set_pk_j != op_pk_j
					let select_chip =
						SelectChipset::new(is_diff_pk_j.clone(), set_pk_j_x, op_pk_j_x);
					let new_op_pk_j_x = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "update op_pk_x"),
					)?;
					op_pk_x_i.push(new_op_pk_j_x);

					let select_chip = SelectChipset::new(is_diff_pk_j, set_pk_j_y, op_pk_j_y);
					let new_op_pk_j_y = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "update op_pk_y"),
					)?;
					op_pk_y_i.push(new_op_pk_j_y);
				}

				// Distribute the scores
				let mut op_score_sum = zero.clone();
				for ops_ij in ops_i.iter().take(NUM_NEIGHBOURS) {
					let add_chip = AddChipset::new(op_score_sum.clone(), ops_ij.clone());
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
					let op_pk_j_x = op_pk_x_i[j].clone();
					let op_pk_j_y = op_pk_y_i[j].clone();

					// Condition 1. op_pk_j != pk_i
					let equal_chip = IsEqualChipset::new(op_pk_j_x.clone(), pk_i_x.clone());
					let is_pk_i_x = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_pk_j_x == pk_i_x"),
					)?;
					let equal_chip = IsEqualChipset::new(op_pk_j_y.clone(), pk_i_y.clone());
					let is_pk_i_y = equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_pk_j_y == pk_i_y"),
					)?;
					let and_chip = AndChipset::new(is_pk_i_x, is_pk_i_y);
					let is_pk_i = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_pk_j == pk_i"),
					)?;
					let sub_chip = SubChipset::new(one.clone(), is_pk_i);
					let is_diff_pk = sub_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_pk_j != pk_i"),
					)?;

					// Condition 2. op_pk_j != PublicKey::default()
					let pk_x_equal_chip =
						IsEqualChipset::new(pk_x[j].clone(), default_pk_x.clone());
					let is_default_pk_x = pk_x_equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "pk_j_x == default_pk_x"),
					)?;

					let pk_y_equal_chip =
						IsEqualChipset::new(pk_y[j].clone(), default_pk_y.clone());
					let is_default_pk_y = pk_y_equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "pk_j_y == default_pk_y"),
					)?;
					let and_chip = AndChipset::new(is_default_pk_x, is_default_pk_y);
					let is_null = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "pk_j == default"),
					)?;
					let sub_chip = SubChipset::new(one.clone(), is_null);
					let is_not_null = sub_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "pk_j != default"),
					)?;

					// Conditions for distributing the score
					// 1. pk_j != pk_i
					// 2. pk_j != PublicKey::default()
					// 3. op_score_sum == 0
					let and_chip = AndChipset::new(is_diff_pk, is_not_null);
					let cond = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_diff_pk && is_not_null"),
					)?;
					let and_chip = AndChipset::new(cond, is_sum_zero.clone());
					let cond = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_diff_pk && is_not_null && is_sum_zero"),
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
			for ops in ops.iter().take(NUM_NEIGHBOURS) {
				let mut ops_i = Vec::new();

				// Compute the sum of scores
				let mut op_score_sum = zero.clone();
				for op in ops.iter().take(NUM_NEIGHBOURS) {
					let add_chip = AddChipset::new(op_score_sum.clone(), op.clone());
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

				for op in ops.iter().take(NUM_NEIGHBOURS) {
					let mul_chip = MulChipset::new(op.clone(), inverted_sum.clone());
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
				let op_i = ops[i].clone();
				let mut sop_i = Vec::new();
				for op in op_i.iter().take(NUM_NEIGHBOURS) {
					let mul_chip = MulChipset::new(op.clone(), s[i].clone());
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
				for sop in sop.iter().take(NUM_NEIGHBOURS) {
					let add_chip = AddChipset::new(new_s[i].clone(), sop[i].clone());
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
		for passed_s in passed_s.iter().take(NUM_NEIGHBOURS) {
			let add_chipset = AddChipset::new(sum.clone(), passed_s.clone());
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

/*
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		calculate_message_hash,
		eddsa::native::{sign, SecretKey},
		utils::{generate_params, prove_and_verify},
	};
	use halo2::{dev::MockProver, halo2curves::bn256::Bn256};
	use rand::thread_rng;

	const NUM_NEIGHBOURS: usize = 5;
	const NUM_ITERATIONS: usize = 20;
	const INITIAL_SCORE: u128 = 1000;

	#[test]
	fn test_closed_graph_circut() {
		let ops: Vec<Vec<Scalar>> = vec![
			vec![0, 200, 300, 500, 0],
			vec![100, 0, 100, 100, 700],
			vec![400, 100, 0, 200, 300],
			vec![100, 100, 700, 0, 100],
			vec![300, 100, 400, 200, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| Scalar::from_u128(x)).collect())
		.collect();

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let op_pub_keys: Vec<Vec<PublicKey>> =
			(0..NUM_NEIGHBOURS).map(|_| pub_keys.to_vec()).collect();

		let (res, signatures) = {
			let mut signatures = vec![];

			let mut et =
				native::EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();
			for i in 0..NUM_NEIGHBOURS {
				et.add_member(pub_keys[i].clone());

				let (_, message_hashes) = calculate_message_hash::<NUM_NEIGHBOURS, 1>(
					op_pub_keys[i].to_vec(),
					vec![ops[i].clone()],
				);
				let sig = sign(&secret_keys[i], &pub_keys[i], message_hashes[0]);
				signatures.push(sig.clone());

				let scores = [0, 1, 2, 3, 4].map(|j| (op_pub_keys[i][j], ops[i][j]));
				let op = native::Opinion::new(sig, message_hashes[0], scores.to_vec());
				et.update_op(pub_keys[i].clone(), op);
			}
			let s = et.converge();

			(s, signatures)
		};

		let et = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new(
			pub_keys.to_vec(),
			signatures,
			op_pub_keys,
			ops,
		);

		let k = 14;
		let prover = match MockProver::<Scalar>::run(k, &et, vec![res.to_vec()]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_closed_graph_circut_prod() {
		let ops: Vec<Vec<Scalar>> = vec![
			vec![0, 200, 300, 500, 0],
			vec![100, 0, 100, 100, 700],
			vec![400, 100, 0, 200, 300],
			vec![100, 100, 700, 0, 100],
			vec![300, 100, 400, 200, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| Scalar::from_u128(x)).collect())
		.collect();
		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let op_pub_keys: Vec<Vec<PublicKey>> =
			(0..NUM_NEIGHBOURS).map(|_| pub_keys.to_vec()).collect();

		let (res, signatures) = {
			let mut signatures = vec![];

			let mut et =
				native::EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();
			for i in 0..NUM_NEIGHBOURS {
				et.add_member(pub_keys[i].clone());

				let (_, message_hashes) = calculate_message_hash::<NUM_NEIGHBOURS, 1>(
					op_pub_keys[i].to_vec(),
					vec![ops[i].clone()],
				);
				let sig = sign(&secret_keys[i], &pub_keys[i], message_hashes[0]);
				signatures.push(sig.clone());

				let scores = [0, 1, 2, 3, 4].map(|j| (op_pub_keys[i][j], ops[i][j]));
				let op = native::Opinion::new(sig, message_hashes[0], scores.to_vec());
				et.update_op(pub_keys[i].clone(), op);
			}
			let s = et.converge();

			(s, signatures)
		};

		let et = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new(
			pub_keys.to_vec(),
			signatures,
			op_pub_keys,
			ops,
		);

		let k = 14;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, et, &[&res], rng).unwrap();
		assert!(res);
	}
}
*/
