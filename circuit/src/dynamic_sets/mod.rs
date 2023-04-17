/// Native version of EigenTrustSet
pub mod native;

use crate::{
	circuit::{Eddsa, FullRoundHasher, PartialRoundHasher, PoseidonHasher, SpongeHasher},
	eddsa::{
		native::{sign, PublicKey, SecretKey, Signature},
		EddsaChipset, EddsaConfig,
	},
	edwards::{
		params::BabyJubJub, IntoAffineChip, PointAddChip, ScalarMulChip, StrictScalarMulConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualConfig, NShiftedChip},
		main::{AddChipset, IsEqualChipset, MainChip, MainConfig, MulChipset},
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::{PoseidonSpongeChipset, PoseidonSpongeConfig},
		FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig,
	},
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	arithmetic::Field,
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::{bn256::Fr as Scalar, FieldExt},
	plonk::{Circuit, ConstraintSystem, Error},
};

use self::native::Opinion;

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
	const SCALE: u128,
> {
	// Public keys
	pk_x: Vec<Value<Scalar>>,
	pk_y: Vec<Value<Scalar>>,
	// Signature
	big_r_x: Vec<Value<Scalar>>,
	big_r_y: Vec<Value<Scalar>>,
	s: Vec<Value<Scalar>>,
	// Opinions
	ops: Vec<Vec<Value<Scalar>>>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	> EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>
{
	/// Constructs a new EigenTrustSet circuit
	pub fn new(pks: Vec<PublicKey>, signatures: Vec<Signature>, ops: Vec<Vec<Scalar>>) -> Self {
		// Pubkey values
		let pk_x = pks.iter().map(|pk| Value::known(pk.0.x.clone())).collect();
		let pk_y = pks.iter().map(|pk| Value::known(pk.0.y.clone())).collect();

		// Signature values
		let big_r_x = signatures.iter().map(|sig| Value::known(sig.big_r.x.clone())).collect();
		let big_r_y = signatures.iter().map(|sig| Value::known(sig.big_r.y.clone())).collect();
		let s = signatures.iter().map(|sig| Value::known(sig.s.clone())).collect();

		// Opinions
		let ops =
			ops.iter().map(|vals| vals.iter().map(|x| Value::known(x.clone())).collect()).collect();

		Self { pk_x, pk_y, big_r_x, big_r_y, s, ops }
	}
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	> Circuit<Scalar> for EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>
{
	type Config = EigenTrustSetConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pk_x: vec![Value::unknown(); NUM_NEIGHBOURS],
			pk_y: vec![Value::unknown(); NUM_NEIGHBOURS],
			big_r_x: vec![Value::unknown(); NUM_NEIGHBOURS],
			big_r_y: vec![Value::unknown(); NUM_NEIGHBOURS],
			s: vec![Value::unknown(); NUM_NEIGHBOURS],
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
			scale,
			ops,
			init_score,
			total_score,
			passed_s,
			one,
			default_pk_x,
			default_pk_y,
		) = layouter.assign_region(
			|| "temp",
			|region: Region<'_, Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);

				let zero = ctx.assign_from_constant(config.common.advice[0], Scalar::zero())?;

				let scale = ctx.assign_from_constant(
					config.common.advice[1],
					Scalar::from_u128(SCALE.pow(NUM_ITER as u32)),
				)?;

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

				let one = ctx.assign_from_constant(config.common.advice[0], Scalar::one())?;

				let default_pk_x = ctx.assign_advice(
					config.common.advice[1],
					Value::known(PublicKey::default().0.x),
				)?;

				let default_pk_y = ctx.assign_advice(
					config.common.advice[2],
					Value::known(PublicKey::default().0.y),
				)?;

				Ok((
					zero, assigned_pk_x, assigned_pk_y, assigned_big_r_x, assigned_big_r_y,
					assigned_s, scale, assigned_ops, assigned_initial_score, assigned_total_score,
					passed_s, one, default_pk_x, default_pk_y,
				))
			},
		)?;

		// signature verification
		{
			let mut pk_sponge = SpongeHasher::new();
			pk_sponge.update(&pk_x);
			pk_sponge.update(&pk_y);
			let keys_message_hash = pk_sponge.synthesize(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "keys_sponge"),
			)?;
			for i in 0..NUM_NEIGHBOURS {
				let mut scores_sponge = SpongeHasher::new();
				scores_sponge.update(&ops[i]);
				let scores_message_hash = scores_sponge.synthesize(
					&config.common,
					&config.sponge,
					layouter.namespace(|| "scores_sponge"),
				)?;
				let message_hash_input = [
					keys_message_hash.clone(),
					scores_message_hash,
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
		}

		// filter peers' ops
		let ops = {
			let mut filtered_ops = vec![];
			for i in 0..NUM_NEIGHBOURS {
				let mut ops_i = vec![];
				let mut op_score_sum = zero.clone();
				for j in 0..NUM_NEIGHBOURS {
					let add_chip = AddChipset::new(op_score_sum.clone(), ops[i][j].clone());
					op_score_sum = add_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_score_sum"),
					)?;
				}

				let equal_chip = IsEqualChipset::new(op_score_sum, zero.clone());
				let is_sum_zero = equal_chip
					.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "op_score_sum == 0"),
					)
					.is_ok();
				if is_sum_zero {
					for j in 0..NUM_NEIGHBOURS {
						let is_diff_pk = i != j;

						let pk_x_equal_chip =
							IsEqualChipset::new(pk_x[j].clone(), default_pk_x.clone());
						let is_default_pk_x = pk_x_equal_chip
							.synthesize(
								&config.common,
								&config.main,
								layouter.namespace(|| "pk_j.x == default_pk.x"),
							)
							.is_ok();

						let pk_y_equal_chip =
							IsEqualChipset::new(pk_y[j].clone(), default_pk_y.clone());
						let is_default_pk_y = pk_y_equal_chip
							.synthesize(
								&config.common,
								&config.main,
								layouter.namespace(|| "pk_j.y == default_pk.y"),
							)
							.is_ok();
						let is_not_null = is_default_pk_x && is_default_pk_y;

						if is_diff_pk && is_not_null {
							ops_i.push(one.clone());
						} else {
							ops_i.push(ops[i][j].clone());
						}
					}
				}
				filtered_ops.push(ops_i);
			}

			filtered_ops
		};

		// compute EigenTrust scores
		{
			let mut s = vec![init_score.clone(); NUM_NEIGHBOURS];
			for _ in 0..NUM_ITER {
				let mut distributions = Vec::new();
				for i in 0..NUM_NEIGHBOURS {
					let op_i = ops[i].clone();
					let mut local_distr = Vec::new();
					for j in 0..NUM_NEIGHBOURS {
						let mul_chip = MulChipset::new(op_i[j].clone(), s[i].clone());
						let res = mul_chip.synthesize(
							&config.common,
							&config.main,
							layouter.namespace(|| "op_mul"),
						)?;
						local_distr.push(res);
					}
					distributions.push(local_distr);
				}

				let mut new_s = vec![zero.clone(); NUM_NEIGHBOURS];
				for i in 0..NUM_NEIGHBOURS {
					for j in 0..NUM_NEIGHBOURS {
						let add_chip =
							AddChipset::new(new_s[i].clone(), distributions[j][i].clone());
						new_s[i] = add_chip.synthesize(
							&config.common,
							&config.main,
							layouter.namespace(|| "op_add"),
						)?;
					}
				}

				s = new_s;
			}

			let mut passed_scaled = Vec::new();
			for i in 0..NUM_NEIGHBOURS {
				let mul_chip = MulChipset::new(passed_s[i].clone(), scale.clone());
				let res = mul_chip.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "op_mul"),
				)?;
				passed_scaled.push(res);
			}

			let mut sum = zero.clone();
			for i in 0..NUM_NEIGHBOURS {
				let add_chipset = AddChipset::new(sum.clone(), passed_s[i].clone());
				sum = add_chipset.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "s_sum"),
				)?;
			}

			layouter.assign_region(
				|| "unscaled_res",
				|region: Region<'_, Scalar>| {
					let ctx = &mut RegionCtx::new(region, 0);
					for i in 0..NUM_NEIGHBOURS {
						let passed_scaled_val = passed_scaled[i].clone();
						let passed_s =
							ctx.copy_assign(config.common.advice[0], passed_scaled_val)?;
						let s = ctx.copy_assign(config.common.advice[1], s[i].clone())?;
						ctx.constrain_equal(passed_s, s)?;
						ctx.next();
					}
					// Constrain the total reputation in the set
					let sum = ctx.copy_assign(config.common.advice[0], sum.clone())?;
					let total_score =
						ctx.copy_assign(config.common.advice[1], total_score.clone())?;
					ctx.constrain_equal(sum, total_score)?;
					Ok(())
				},
			)?;
		}

		Ok(())
	}
}
