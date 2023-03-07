use crate::{
	eddsa::{
		native::{sign, PublicKey, SecretKey, Signature},
		EddsaChipset, EddsaConfig,
	},
	edwards::{
		params::{BabyJubJub, EdwardsParams},
		IntoAffineChip, PointAddChip, ScalarMulChip, StrictScalarMulConfig,
	},
	gadgets::{
		absorb::AbsorbChip,
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualConfig, NShiftedChip, N_SHIFTED},
		main::{AddChipset, MainChip, MainConfig, MulChipset},
		range::{LookupRangeCheckChip, LookupRangeCheckChipsetConfig, LookupShortWordCheckChip},
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::{PoseidonSpongeChipset, PoseidonSpongeConfig},
		FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig,
	},
	utils::to_bits,
	Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
};
use halo2::{
	arithmetic::Field,
	circuit::{Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::{bn256::Fr as Scalar, FieldExt},
	plonk::{Circuit, ConstraintSystem, Error},
};
use rand::Rng;

const HASHER_WIDTH: usize = 5;
/// Type alias for the native poseidon hasher with a width of 5 and bn254 params
pub type PoseidonNativeHasher = Poseidon<Scalar, HASHER_WIDTH, Params>;
/// Type alias for native poseidon sponge with a width of 5 and bn254 params
pub type PoseidonNativeSponge = PoseidonSponge<Scalar, HASHER_WIDTH, Params>;
/// Type alias for the poseidon hasher chip with a width of 5 and bn254 params
pub type PoseidonHasher = PoseidonChipset<Scalar, HASHER_WIDTH, Params>;
/// Partial rounds of permulation chip
type PartialRoundHasher = PartialRoundChip<Scalar, HASHER_WIDTH, Params>;
/// Full rounds of permuation chip
type FullRoundHasher = FullRoundChip<Scalar, HASHER_WIDTH, Params>;
/// Type alias for the poseidon spong chip with a width of 5 and bn254 params
pub type SpongeHasher = PoseidonSpongeChipset<Scalar, HASHER_WIDTH, Params>;
/// Type alias for Eddsa chip on BabyJubJub elliptic curve
type Eddsa = EddsaChipset<Scalar, BabyJubJub, Params>;

#[derive(Clone, Debug)]
/// The columns config for the main circuit.
pub struct EigenTrustConfig {
	common: CommonConfig,
	main: MainConfig,
	sponge: PoseidonSpongeConfig,
	poseidon: PoseidonConfig,
	eddsa: EddsaConfig,
}

#[derive(Clone)]
/// Structure of the main EigenTrust circuit
pub struct EigenTrust<
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
	// Bits
	s_bits: Vec<[Scalar; 252]>,
	suborder_bits: [Scalar; 252],
	s_suborder_diff_bits: Vec<[Scalar; 253]>,
	m_hash_bits: Vec<[Scalar; 256]>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	> EigenTrust<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>
{
	/// Constructs a new EigenTrust circuit
	pub fn new(
		pks: Vec<PublicKey>, signatures: Vec<Signature>, ops: Vec<Vec<Scalar>>,
		messages: Vec<Scalar>,
	) -> Self {
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

		let s_bits = signatures
			.iter()
			.map(|sig| sig.s.to_bytes())
			.map(|s| to_bits(s).map(Scalar::from))
			.collect();
		let suborder = BabyJubJub::suborder();
		let suborder_bits = to_bits(suborder.to_bytes()).map(Scalar::from);
		let diffs =
			signatures.iter().map(|sig| sig.s + Scalar::from_bytes(&N_SHIFTED).unwrap() - suborder);
		let diff_bits = diffs.map(|diff| to_bits(diff.to_bytes()).map(Scalar::from)).collect();

		let m_hash_bits = pks
			.iter()
			.zip(signatures)
			.zip(messages)
			.map(|((pk, sig), msg)| {
				let h_inputs = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, msg];
				let res = PoseidonNativeHasher::new(h_inputs).permute()[0];
				let m_hash_bits = to_bits(res.to_bytes()).map(Scalar::from);
				m_hash_bits
			})
			.collect();

		Self {
			pk_x,
			pk_y,
			big_r_x,
			big_r_y,
			s,
			ops,
			s_bits,
			suborder_bits,
			s_suborder_diff_bits: diff_bits,
			m_hash_bits,
		}
	}

	/// Make a new circuit with the inputs being random values.
	pub fn random<R: Rng + Clone>(rng: &mut R) -> Self {
		let mut pks = Vec::new();
		let mut messages = Vec::new();
		let mut sigs = Vec::new();
		let mut ops = Vec::new();

		for _ in 0..NUM_NEIGHBOURS {
			let sk = SecretKey::random(rng);
			let pk = sk.public();

			let mut neighbour_ops = Vec::new();
			for _ in 0..NUM_NEIGHBOURS {
				neighbour_ops.push(Scalar::random(rng.clone()));
			}

			let msg = Scalar::random(rng.clone());
			let sig = sign(&sk, &pk, msg.clone());

			pks.push(pk);
			messages.push(msg);
			sigs.push(sig);
			ops.push(neighbour_ops);
		}

		EigenTrust::new(pks, sigs, ops, messages)
	}
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITER: usize,
		const INITIAL_SCORE: u128,
		const SCALE: u128,
	> Circuit<Scalar> for EigenTrust<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>
{
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pk_x: vec![Value::unknown(); NUM_NEIGHBOURS],
			pk_y: vec![Value::unknown(); NUM_NEIGHBOURS],
			big_r_x: vec![Value::unknown(); NUM_NEIGHBOURS],
			big_r_y: vec![Value::unknown(); NUM_NEIGHBOURS],
			s: vec![Value::unknown(); NUM_NEIGHBOURS],
			ops: vec![vec![Value::unknown(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			s_bits: vec![[Scalar::zero(); 252]; NUM_NEIGHBOURS],
			suborder_bits: [Scalar::zero(); 252],
			s_suborder_diff_bits: vec![[Scalar::zero(); 253]; NUM_NEIGHBOURS],
			m_hash_bits: vec![[Scalar::zero(); 256]; NUM_NEIGHBOURS],
		}
	}

	fn configure(meta: &mut ConstraintSystem<Scalar>) -> EigenTrustConfig {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let full_round_selector = FullRoundHasher::configure(&common, meta);
		let partial_round_selector = PartialRoundHasher::configure(&common, meta);
		let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

		let absorb_selector = AbsorbChip::<Scalar, HASHER_WIDTH>::configure(&common, meta);
		let sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

		let bits2num_selector = Bits2NumChip::configure(&common, meta);
		let n_shifted_selector = NShiftedChip::configure(&common, meta);
		let running_sum_selector = LookupRangeCheckChip::<Scalar, 8, 32>::configure(&common, meta);
		let lookup_short_word_selector =
			LookupShortWordCheckChip::<Scalar, 8, 4>::configure(&common, meta);
		let lookup_range_check_config =
			LookupRangeCheckChipsetConfig::new(running_sum_selector, lookup_short_word_selector);
		let lt_eq = LessEqualConfig::new(
			main.clone(),
			lookup_range_check_config,
			bits2num_selector,
			n_shifted_selector,
		);

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

		EigenTrustConfig { common, main, eddsa, sponge, poseidon }
	}

	fn synthesize(
		&self, config: EigenTrustConfig, mut layouter: impl Layouter<Scalar>,
	) -> Result<(), Error> {
		// Loads the values [0..2^8) into table column for lookup range check.
		layouter.assign_table(
			|| "table_column",
			|mut table| {
				// We generate the row values lazily (we only need them during keygen).
				for index in 0..(1 << 8) {
					table.assign_cell(
						|| "table_column",
						config.common.table,
						index,
						|| Value::known(Scalar::from(index as u64)),
					)?;
				}
				Ok(())
			},
		)?;

		let (zero, pk_x, pk_y, big_r_x, big_r_y, s, scale, ops, init_score, total_score, passed_s) =
			layouter.assign_region(
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

					Ok((
						zero, assigned_pk_x, assigned_pk_y, assigned_big_r_x, assigned_big_r_y,
						assigned_s, scale, assigned_ops, assigned_initial_score,
						assigned_total_score, passed_s,
					))
				},
			)?;

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
				self.s_bits[i],
				self.suborder_bits,
				self.s_suborder_diff_bits[i],
				self.m_hash_bits[i],
			);
			eddsa.synthesize(
				&config.common,
				&config.eddsa,
				layouter.namespace(|| "eddsa"),
			)?;
		}

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
					let add_chip = AddChipset::new(new_s[i].clone(), distributions[j][i].clone());
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
					let passed_s = ctx.copy_assign(config.common.advice[0], passed_scaled_val)?;
					let s = ctx.copy_assign(config.common.advice[1], s[i].clone())?;
					ctx.constrain_equal(passed_s, s)?;
					ctx.next();
				}
				// Constrain the total reputation in the set
				let sum = ctx.copy_assign(config.common.advice[0], sum.clone())?;
				let total_score = ctx.copy_assign(config.common.advice[1], total_score.clone())?;
				ctx.constrain_equal(sum, total_score)?;
				Ok(())
			},
		)?;

		Ok(())
	}
}

/// Native version of EigenTrust algorithm
pub fn native<F: FieldExt, const N: usize, const I: usize, const S: u128>(
	mut s: Vec<F>, ops: Vec<Vec<F>>,
) -> Vec<F> {
	assert!(s.len() == N);
	assert!(ops.len() == N);
	for i in 0..N {
		assert!(ops[i].len() == N);
	}

	for _ in 0..I {
		let mut distributions = Vec::new();
		for i in 0..N {
			let ops_i = &ops[i];
			let mut local_distr = Vec::new();
			for j in 0..N {
				let op = ops_i[j] * s[i];
				local_distr.push(op);
			}
			distributions.push(local_distr);
		}

		let mut new_s = vec![F::zero(); N];
		for i in 0..N {
			for j in 0..N {
				new_s[i] += distributions[j][i];
			}
		}

		s = new_s;
	}

	for i in 0..N {
		let big_scale = F::from_u128(S.pow(I as u32));
		let big_scale_inv = big_scale.invert().unwrap();
		s[i] = s[i] * big_scale_inv;
		println!("unscaled: {:?}", s[i]);
	}

	let mut sum = F::zero();
	for x in s.iter() {
		sum += x;
	}
	println!("sum: {:?}", sum);

	s
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		eddsa::native::{sign, SecretKey},
		utils::{generate_params, prove_and_verify},
		verifier::{evm_verify, gen_evm_verifier, gen_pk, gen_proof, gen_srs},
	};
	use halo2::{dev::MockProver, halo2curves::bn256::Bn256};
	use rand::thread_rng;

	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;

	#[test]
	fn test_closed_graph_circut() {
		let s = vec![Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
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
		let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops.clone());

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages: Vec<Scalar> = ops
			.iter()
			.map(|scores| {
				let mut sponge = PoseidonNativeSponge::new();
				sponge.update(&scores);
				let scores_message_hash = sponge.squeeze();

				let m_inputs = [
					keys_message_hash,
					scores_message_hash,
					Scalar::zero(),
					Scalar::zero(),
					Scalar::zero(),
				];
				let poseidon = PoseidonNativeHasher::new(m_inputs);
				let res = poseidon.permute()[0];
				res
			})
			.collect();

		let signatures: Vec<Signature> = secret_keys
			.into_iter()
			.zip(pub_keys.clone())
			.zip(messages.clone())
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg))
			.collect();

		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys.to_vec(),
			signatures,
			ops,
			messages,
		);

		let k = 14;
		let prover = match MockProver::<Scalar>::run(k, &et, vec![res.to_vec()]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		// let errs = prover.verify().err().unwrap();
		// for err in errs {
		// 	println!("{:#?}", err);
		// }

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_closed_graph_circut_prod() {
		let s = vec![Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
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
		let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops.clone());

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages: Vec<Scalar> = ops
			.iter()
			.map(|scores| {
				let mut sponge = PoseidonNativeSponge::new();
				sponge.update(&scores);
				let scores_message_hash = sponge.squeeze();

				let m_inputs = [
					keys_message_hash,
					scores_message_hash,
					Scalar::zero(),
					Scalar::zero(),
					Scalar::zero(),
				];
				let poseidon = PoseidonNativeHasher::new(m_inputs);
				let res = poseidon.permute()[0];
				res
			})
			.collect();

		let signatures: Vec<Signature> = secret_keys
			.into_iter()
			.zip(pub_keys.clone())
			.zip(messages.clone())
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg))
			.collect();

		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys.to_vec(),
			signatures,
			ops,
			messages,
		);

		let k = 14;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, et, &[&res], rng).unwrap();
		assert!(res);
	}

	#[test]
	fn test_closed_graph_circut_evm() {
		let s = vec![Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
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
		let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops.clone());

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages: Vec<Scalar> = ops
			.iter()
			.map(|scores| {
				let mut sponge = PoseidonNativeSponge::new();
				sponge.update(&scores);
				let scores_message_hash = sponge.squeeze();

				let m_inputs = [
					keys_message_hash,
					scores_message_hash,
					Scalar::zero(),
					Scalar::zero(),
					Scalar::zero(),
				];
				let poseidon = PoseidonNativeHasher::new(m_inputs);
				let res = poseidon.permute()[0];
				res
			})
			.collect();

		let signatures: Vec<Signature> = secret_keys
			.into_iter()
			.zip(pub_keys.clone())
			.zip(messages.clone())
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg))
			.collect();

		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys.to_vec(),
			signatures,
			ops,
			messages,
		);

		let k = 14;
		let params = gen_srs(k);
		let pk = gen_pk(&params, &et);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
		dbg!(deployment_code.len());

		let proof = gen_proof(&params, &pk, et.clone(), vec![res.clone()]);
		evm_verify(deployment_code, vec![res], proof);
	}
}
