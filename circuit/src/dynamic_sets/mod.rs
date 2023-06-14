/// Native version of EigenTrustSet
pub mod native;
use crate::eddsa::native::Signature;
use crate::UnassignedValue;

/// Native version of EigenTrustSet(ECDSA)  
///
/// NOTE: This is temporary since Halo2 version of ECDSA is not ready
pub mod ecdsa_native;

use crate::{
	circuit::{Eddsa, FullRoundHasher, PartialRoundHasher, PoseidonHasher, SpongeHasher},
	eddsa::{
		native::{PublicKey, UnassignedPublicKey, UnassignedSignature},
		EddsaConfig,
	},
	edwards::{
		params::BabyJubJub, IntoAffineChip, PointAddChip, ScalarMulChip, StrictScalarMulConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualConfig, NShiftedChip},
		main::{
			AddChipset, AndChipset, InverseChipset, IsEqualChipset, MainChip, MainConfig,
			MulChipset, OrChipset, SelectChipset, SubChipset,
		},
	},
	poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::{bn256::Fr as Scalar, ff::PrimeField},
	plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;

const HASHER_WIDTH: usize = 5;

#[derive(Clone, Debug)]
/// The columns config for the EigenTrustSet circuit.
pub struct EigenTrustSetConfig {
	common: CommonConfig,
	main: MainConfig,
	sponge: PoseidonSpongeConfig,
	poseidon: PoseidonConfig,
	eddsa: EddsaConfig,
}

#[derive(Clone, Debug)]
/// Structure of the EigenTrustSet circuit
pub struct EigenTrustSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITER: usize,
	const INITIAL_SCORE: u128,
> {
	// Public keys
	pk_x: Vec<Value<Scalar>>,
	pk_y: Vec<Value<Scalar>>,
	// Signature
	big_r_x: Vec<Value<Scalar>>,
	big_r_y: Vec<Value<Scalar>>,
	s: Vec<Value<Scalar>>,
	// Opinions
	op_pk_x: Vec<Vec<Value<Scalar>>>,
	op_pk_y: Vec<Vec<Value<Scalar>>>,
	ops: Vec<Vec<Value<Scalar>>>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITER: usize, const INITIAL_SCORE: u128>
	EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE>
{
	/// Constructs a new EigenTrustSet circuit
	pub fn new(
		pks: Vec<PublicKey>, signatures: Vec<Signature>, op_pks: Vec<Vec<PublicKey>>,
		ops: Vec<Vec<Scalar>>,
	) -> Self {
		// Pubkey values
		let pks = pks.into_iter().map(|x| UnassignedPublicKey::from(x)).collect_vec();
		let pk_x = pks.iter().map(|pk| pk.0.x.clone()).collect();
		let pk_y = pks.iter().map(|pk| pk.0.y.clone()).collect();

		// Signature values
		let signatures = signatures.into_iter().map(|x| UnassignedSignature::from(x)).collect_vec();
		let big_r_x = signatures.iter().map(|sig| sig.big_r.x.clone()).collect();
		let big_r_y = signatures.iter().map(|sig| sig.big_r.y.clone()).collect();
		let s = signatures.iter().map(|sig| sig.s.clone()).collect();

		// Opinions
		let op_pks = op_pks
			.into_iter()
			.map(|pks| pks.into_iter().map(|pk| UnassignedPublicKey::from(pk)).collect_vec())
			.collect_vec();
		let op_pk_x =
			op_pks.iter().map(|pks| pks.iter().map(|pk| pk.0.x.clone()).collect()).collect();
		let op_pk_y =
			op_pks.iter().map(|pks| pks.iter().map(|pk| pk.0.y.clone()).collect()).collect();
		let ops =
			ops.iter().map(|vals| vals.iter().map(|x| Value::known(x.clone())).collect()).collect();

		Self { pk_x, pk_y, big_r_x, big_r_y, s, op_pk_x, op_pk_y, ops }
	}
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITER: usize, const INITIAL_SCORE: u128> Circuit<Scalar>
	for EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE>
{
	type Config = EigenTrustSetConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		let pk = UnassignedPublicKey::without_witnesses();
		let sig = UnassignedSignature::without_witnesses();
		let op_pk = UnassignedPublicKey::without_witnesses();
		Self {
			pk_x: vec![pk.0.x; NUM_NEIGHBOURS],
			pk_y: vec![pk.0.y; NUM_NEIGHBOURS],
			big_r_x: vec![sig.big_r.x; NUM_NEIGHBOURS],
			big_r_y: vec![sig.big_r.y; NUM_NEIGHBOURS],
			s: vec![sig.s; NUM_NEIGHBOURS],
			op_pk_x: vec![vec![op_pk.0.x; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			op_pk_y: vec![vec![op_pk.0.y; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			ops: vec![vec![Value::unknown(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
		}
	}

	fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let full_round_selector = FullRoundHasher::configure(&common, meta);
		let partial_round_selector = PartialRoundHasher::configure(&common, meta);
		let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

		let absorb_selector = AbsorbChip::<Scalar, HASHER_WIDTH>::configure(&common, meta);
		let sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

		let bits2num_selector = Bits2NumChip::configure(&common, meta);
		let n_shifted_selector = NShiftedChip::configure(&common, meta);
		let lt_eq = LessEqualConfig::new(main.clone(), bits2num_selector, n_shifted_selector);

		let scalar_mul_selector = ScalarMulChip::<_, BabyJubJub>::configure(&common, meta);
		let strict_scalar_mul = StrictScalarMulConfig::new(bits2num_selector, scalar_mul_selector);

		let add_point_selector = PointAddChip::<_, BabyJubJub>::configure(&common, meta);
		let affine_selector = IntoAffineChip::configure(&common, meta);

		let eddsa = EddsaConfig::new(
			poseidon.clone(),
			lt_eq,
			strict_scalar_mul,
			add_point_selector,
			affine_selector,
		);

		EigenTrustSetConfig { common, main, eddsa, sponge, poseidon }
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl Layouter<Scalar>,
	) -> Result<(), Error> {
		let (
			zero,
			pk_x,
			pk_y,
			big_r_x,
			big_r_y,
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
		) = layouter.assign_region(
			|| "temp",
			|region: Region<'_, Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);

				let zero = ctx.assign_from_constant(config.common.advice[0], Scalar::zero())?;

				let assigned_initial_score = ctx.assign_from_constant(
					config.common.advice[2],
					Scalar::from_u128(INITIAL_SCORE),
				)?;

				let assigned_total_score = ctx.assign_from_constant(
					config.common.advice[3],
					Scalar::from_u128(INITIAL_SCORE * NUM_NEIGHBOURS as u128),
				)?;

				// Move to the next row
				ctx.next();

				let mut assigned_pk_x = Vec::new();
				for chunk in self.pk_x.chunks(ADVICE) {
					for i in 0..chunk.len() {
						let val = chunk[i].clone();
						let pk_x = ctx.assign_advice(config.common.advice[i], val)?;
						assigned_pk_x.push(pk_x)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_pk_y = Vec::new();
				for chunk in self.pk_y.chunks(ADVICE) {
					for i in 0..chunk.len() {
						let val = chunk[i].clone();
						let pk_y = ctx.assign_advice(config.common.advice[i], val)?;
						assigned_pk_y.push(pk_y)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_big_r_x = Vec::new();
				for chunk in self.big_r_x.chunks(ADVICE) {
					for i in 0..chunk.len() {
						let val = chunk[i].clone();
						let big_r_x = ctx.assign_advice(config.common.advice[i], val)?;
						assigned_big_r_x.push(big_r_x)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_big_r_y = Vec::new();
				for chunk in self.big_r_y.chunks(ADVICE) {
					for i in 0..chunk.len() {
						let val = chunk[i].clone();
						let big_r_y = ctx.assign_advice(config.common.advice[i], val)?;
						assigned_big_r_y.push(big_r_y)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_s = Vec::new();
				for chunk in self.s.chunks(ADVICE) {
					for i in 0..chunk.len() {
						let val = chunk[i].clone();
						let s = ctx.assign_advice(config.common.advice[i], val)?;
						assigned_s.push(s)
					}
					// Move to the next row
					ctx.next();
				}

				let mut assigned_ops = Vec::new();
				for neighbour_ops in &self.ops {
					let mut assigned_neighbour_op = Vec::new();
					for chunk in neighbour_ops.chunks(ADVICE) {
						for i in 0..chunk.len() {
							let val = chunk[i].clone();
							let s = ctx.assign_advice(config.common.advice[i], val)?;
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

				let one = ctx.assign_from_constant(config.common.advice[0], Scalar::one())?;

				let default_pk_x = ctx.assign_advice(
					config.common.advice[1],
					Value::known(PublicKey::default().0.x),
				)?;

				let default_pk_y = ctx.assign_advice(
					config.common.advice[2],
					Value::known(PublicKey::default().0.y),
				)?;
				ctx.next();

				let mut assigned_op_pk_x = Vec::new();
				for neighbour_pk_x in &self.op_pk_x {
					let mut assigned_neighbour_pk_x = Vec::new();
					for chunk in neighbour_pk_x.chunks(ADVICE) {
						for i in 0..chunk.len() {
							let val = chunk[i].clone();
							let x = ctx.assign_advice(config.common.advice[i], val)?;
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
						for i in 0..chunk.len() {
							let val = chunk[i];
							let y = ctx.assign_advice(config.common.advice[i], val)?;
							assigned_neighbour_pk_y.push(y);
						}
						// Move to the next row
						ctx.next();
					}
					assigned_op_pk_y.push(assigned_neighbour_pk_y);
				}

				Ok((
					zero, assigned_pk_x, assigned_pk_y, assigned_big_r_x, assigned_big_r_y,
					assigned_s, assigned_ops, assigned_initial_score, assigned_total_score,
					passed_s, one, default_pk_x, default_pk_y, assigned_op_pk_x, assigned_op_pk_y,
				))
			},
		)?;

		// signature verification
		let zero_state = [zero.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone()];
		let mut pk_sponge = SpongeHasher::new(zero_state.clone(), zero.clone());
		pk_sponge.update(&pk_x);
		pk_sponge.update(&pk_y);
		let pks_hash = pk_sponge.synthesize(
			&config.common,
			&config.sponge,
			layouter.namespace(|| "pks_sponge"),
		)?;

		for i in 0..NUM_NEIGHBOURS {
			let mut scores_sponge = SpongeHasher::new(zero_state.clone(), zero.clone());
			scores_sponge.update(&ops[i]);
			let scores_message_hash = scores_sponge.synthesize(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "scores_sponge"),
			)?;
			let message_hash_input = [
				pks_hash[0].clone(),
				scores_message_hash[0].clone(),
				zero.clone(),
				zero.clone(),
				zero.clone(),
			];
			let poseidon = PoseidonHasher::new(message_hash_input);
			let res = poseidon.synthesize(
				&config.common,
				&config.poseidon,
				layouter.namespace(|| "message_hash"),
			)?;

			let eddsa = Eddsa::new(
				big_r_x[i].clone(),
				big_r_y[i].clone(),
				s[i].clone(),
				pk_x[i].clone(),
				pk_y[i].clone(),
				res[0].clone(),
			);
			eddsa.synthesize(
				&config.common,
				&config.eddsa,
				layouter.namespace(|| "eddsa"),
			)?;
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
			|region: Region<'_, Scalar>| {
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
			|region: Region<'_, Scalar>| {
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
		calculate_message_hash,
		eddsa::native::{sign, SecretKey},
		utils::{generate_params, prove_and_verify, read_params},
		verifier::{evm_verify, gen_evm_verifier, gen_pk, gen_proof},
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

		let k = 15;
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

		let k = 15;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, et, &[&res], rng).unwrap();
		assert!(res);
	}

	#[test]
	fn test_closed_graph_circut_evm() {
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

		let k = 15;
		let params = read_params(k);
		let pk = gen_pk(&params, &et);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
		dbg!(deployment_code.len());

		let proof = gen_proof(&params, &pk, et, vec![res.clone()]);
		evm_verify(deployment_code, vec![res], proof);
	}
}
