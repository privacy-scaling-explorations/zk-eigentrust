use crate::{
	eddsa::{
		native::{sign, PublicKey, SecretKey, Signature},
		EddsaChip, EddsaConfig,
	},
	edwards::params::{BabyJubJub, EdwardsParams},
	gadgets::{
		bits2num::to_bits,
		common::{CommonChip, CommonConfig},
		lt_eq::N_SHIFTED,
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::{PoseidonSpongeChip, PoseidonSpongeConfig},
		PoseidonChipset,
	},
	RegionCtx,
};
use halo2::{
	arithmetic::Field,
	circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
	halo2curves::{bn256::Fr as Scalar, FieldExt},
	plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
};
use rand::Rng;

/// Type alias for the native poseidon hasher with a width of 5 and bn254 params
pub type PoseidonNativeHasher = Poseidon<Scalar, 5, Params>;
/// Type alias for native poseidon sponge with a width of 5 and bn254 params
pub type PoseidonNativeSponge = PoseidonSponge<Scalar, 5, Params>;
/// Type alias for the poseidon hasher chip with a width of 5 and bn254 params
pub type PoseidonHasher = PoseidonChipset<Scalar, 5, Params>;
/// Type alias for the poseidon spong chip with a width of 5 and bn254 params
pub type SpongeHasher = PoseidonSpongeChip<Scalar, 5, Params>;
/// Type alias for Eddsa chip on BabyJubJub elliptic curve
type Eddsa = EddsaChip<Scalar, BabyJubJub, Params>;

#[derive(Clone, Debug)]
/// The columns config for the main circuit.
pub struct EigenTrustConfig {
	common: CommonConfig,
	eddsa: EddsaConfig,
	sponge: PoseidonSpongeConfig<5>,
	temp: Column<Advice>,
	fixed: Column<Fixed>,
	instance: Column<Instance>,
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
	pk_x: [Value<Scalar>; NUM_NEIGHBOURS],
	pk_y: [Value<Scalar>; NUM_NEIGHBOURS],
	// Signature
	big_r_x: [Value<Scalar>; NUM_NEIGHBOURS],
	big_r_y: [Value<Scalar>; NUM_NEIGHBOURS],
	s: [Value<Scalar>; NUM_NEIGHBOURS],
	// Opinions
	ops: [[Value<Scalar>; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
	// Bits
	s_bits: [[Scalar; 252]; NUM_NEIGHBOURS],
	suborder_bits: [Scalar; 252],
	s_suborder_diff_bits: [[Scalar; 253]; NUM_NEIGHBOURS],
	m_hash_bits: [[Scalar; 256]; NUM_NEIGHBOURS],
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
		pks: [PublicKey; NUM_NEIGHBOURS], signatures: [Signature; NUM_NEIGHBOURS],
		ops: [[Scalar; NUM_NEIGHBOURS]; NUM_NEIGHBOURS], messages: [Scalar; NUM_NEIGHBOURS],
	) -> Self {
		// Pubkey values
		let pk_x = pks.clone().map(|pk| Value::known(pk.0.x));
		let pk_y = pks.clone().map(|pk| Value::known(pk.0.y));

		// Signature values
		let big_r_x = signatures.clone().map(|sig| Value::known(sig.big_r.x));
		let big_r_y = signatures.clone().map(|sig| Value::known(sig.big_r.y));
		let s = signatures.clone().map(|sig| Value::known(sig.s));

		// Opinions
		let ops = ops.map(|vals| vals.map(|x| Value::known(x)));

		let s_bits =
			signatures.clone().map(|sig| sig.s.to_bytes()).map(|s| to_bits(s).map(Scalar::from));
		let suborder = BabyJubJub::suborder();
		let suborder_bits = to_bits(suborder.to_bytes()).map(Scalar::from);
		let diffs = signatures
			.clone()
			.map(|sig| sig.s + Scalar::from_bytes(&N_SHIFTED).unwrap() - suborder);
		let diff_bits = diffs.map(|diff| to_bits(diff.to_bytes()).map(Scalar::from));

		let m_hash_bits = pks.zip(signatures).zip(messages).map(|((pk, sig), msg)| {
			let h_inputs = [sig.big_r.x, sig.big_r.y, pk.0.x, pk.0.y, msg];
			let res = PoseidonNativeHasher::new(h_inputs).permute()[0];
			let m_hash_bits = to_bits(res.to_bytes()).map(Scalar::from);
			m_hash_bits
		});

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
		let sks = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pks = sks.clone().map(|x| x.public());
		let ops = [[(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS]
			.map(|arr| arr.map(|_| Scalar::random(rng.clone())));
		let messages = [(); NUM_NEIGHBOURS].map(|_| Scalar::random(rng.clone()));
		let signatures =
			sks.zip(pks.clone()).zip(messages).map(|((sk, pk), msg)| sign(&sk, &pk, msg));

		EigenTrust::new(pks, signatures, ops, messages)
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
			pk_x: [Value::unknown(); NUM_NEIGHBOURS],
			pk_y: [Value::unknown(); NUM_NEIGHBOURS],
			big_r_x: [Value::unknown(); NUM_NEIGHBOURS],
			big_r_y: [Value::unknown(); NUM_NEIGHBOURS],
			s: [Value::unknown(); NUM_NEIGHBOURS],
			ops: [[Value::unknown(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
			s_bits: [[Scalar::zero(); 252]; NUM_NEIGHBOURS],
			suborder_bits: [Scalar::zero(); 252],
			s_suborder_diff_bits: [[Scalar::zero(); 253]; NUM_NEIGHBOURS],
			m_hash_bits: [[Scalar::zero(); 256]; NUM_NEIGHBOURS],
		}
	}

	fn configure(meta: &mut ConstraintSystem<Scalar>) -> EigenTrustConfig {
		let common = CommonChip::configure(meta);
		let eddsa = Eddsa::configure(meta);
		let sponge = SpongeHasher::configure(meta);
		let temp = meta.advice_column();
		let fixed = meta.fixed_column();
		let instance = meta.instance_column();

		meta.enable_equality(temp);
		meta.enable_equality(fixed);
		meta.enable_equality(instance);

		EigenTrustConfig { common, eddsa, sponge, temp, fixed, instance }
	}

	fn synthesize(
		&self, config: EigenTrustConfig, mut layouter: impl Layouter<Scalar>,
	) -> Result<(), Error> {
		let (zero, pk_x, pk_y, big_r_x, big_r_y, s, scale, ops, init_score, passed_s) = layouter
			.assign_region(
				|| "temp",
				|region: Region<'_, Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let zero_fixed = ctx.assign_fixed(config.fixed, Scalar::zero())?;
					let zero = ctx.assign_advice(config.temp, Value::known(Scalar::zero()))?;
					ctx.constrain_equal(zero_fixed, zero.clone())?;
					ctx.next();
					let assigned_pk_x = self.pk_x.try_map(|v| {
						let val = ctx.assign_advice(config.temp, v);
						ctx.next();
						val
					})?;
					let assigned_pk_y = self.pk_y.try_map(|v| {
						let val = ctx.assign_advice(config.temp, v);
						ctx.next();
						val
					})?;
					let assigned_big_r_x = self.big_r_x.try_map(|v| {
						let val = ctx.assign_advice(config.temp, v);
						ctx.next();
						val
					})?;
					let assigned_big_r_y = self.big_r_y.try_map(|v| {
						let val = ctx.assign_advice(config.temp, v);
						ctx.next();
						val
					})?;
					let assigned_s = self.s.try_map(|v| {
						let val = ctx.assign_advice(config.temp, v);
						ctx.next();
						val
					})?;
					let scale_fixed = ctx.assign_fixed(
						config.fixed,
						Scalar::from_u128(SCALE.pow(NUM_ITER as u32)),
					)?;
					let scale = ctx.assign_advice(
						config.temp,
						Value::known(Scalar::from_u128(SCALE.pow(NUM_ITER as u32))),
					)?;
					ctx.constrain_equal(scale_fixed, scale.clone())?;
					ctx.next();

					let initial_score_fixed =
						ctx.assign_fixed(config.fixed, Scalar::from_u128(INITIAL_SCORE))?;
					let assigned_initial_score = ctx.assign_advice(
						config.temp,
						Value::known(Scalar::from_u128(INITIAL_SCORE)),
					)?;
					ctx.constrain_equal(initial_score_fixed, assigned_initial_score.clone())?;
					ctx.next();

					let assigned_ops = self.ops.try_map(|vs| {
						vs.try_map(|v| {
							let val = ctx.assign_advice(config.temp, v);
							ctx.next();
							val
						})
					})?;

					let mut passed_s: [Option<AssignedCell<Scalar, Scalar>>; NUM_NEIGHBOURS] =
						[(); NUM_NEIGHBOURS].map(|_| None);

					for i in 0..NUM_NEIGHBOURS {
						let ps = ctx.assign_from_instance(config.temp, config.instance, i)?;
						passed_s[i] = Some(ps);
						ctx.next();
					}
					let unwrapped_passed_s = passed_s.map(|x| x.unwrap());

					Ok((
						zero, assigned_pk_x, assigned_pk_y, assigned_big_r_x, assigned_big_r_y,
						assigned_s, scale, assigned_ops, assigned_initial_score,
						unwrapped_passed_s,
					))
				},
			)?;

		let mut pk_sponge = SpongeHasher::new();
		pk_sponge.update(&pk_x);
		pk_sponge.update(&pk_y);
		let keys_message_hash =
			pk_sponge.squeeze(&config.sponge, layouter.namespace(|| "keys_sponge"))?;
		for i in 0..NUM_NEIGHBOURS {
			let mut scores_sponge = SpongeHasher::new();
			scores_sponge.update(&ops[i]);
			let scores_message_hash =
				scores_sponge.squeeze(&config.sponge, layouter.namespace(|| "scores_sponge"))?;
			let message_hash_input = [
				keys_message_hash.clone(),
				scores_message_hash,
				zero.clone(),
				zero.clone(),
				zero.clone(),
			];
			let poseidon = PoseidonHasher::new(message_hash_input);
			let res = poseidon.synthesize(
				&config.sponge.poseidon_config,
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
			eddsa.synthesize(&config.eddsa, layouter.namespace(|| "eddsa"))?;
		}

		let mut s = [(); NUM_NEIGHBOURS].map(|_| init_score.clone());

		for _ in 0..NUM_ITER {
			let mut distributions =
				[[(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS].map(|arr| arr.map(|_| zero.clone()));
			for j in 0..NUM_NEIGHBOURS {
				let op_j = ops[j].clone();
				distributions[j] = op_j.try_map(|v| {
					CommonChip::mul(
						v,
						s[j].clone(),
						&config.common,
						layouter.namespace(|| "op_mul"),
					)
				})?;
			}

			let mut new_s = [(); NUM_NEIGHBOURS].map(|_| zero.clone());
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					new_s[i] = CommonChip::add(
						new_s[i].clone(),
						distributions[j][i].clone(),
						&config.common,
						layouter.namespace(|| "op_add"),
					)?;
				}
			}

			s = new_s;
		}

		let mut passed_scaled = [(); NUM_NEIGHBOURS].map(|_| zero.clone());
		for i in 0..NUM_NEIGHBOURS {
			passed_scaled[i] = CommonChip::mul(
				passed_s[i].clone(),
				scale.clone(),
				&config.common,
				layouter.namespace(|| "op_mul"),
			)?;
		}

		layouter.assign_region(
			|| "unscaled_res",
			|region: Region<'_, Scalar>| {
				let ctx = &mut RegionCtx::new(region, 0);
				for i in 0..NUM_NEIGHBOURS {
					let passed_s = ctx.copy_assign(config.temp, passed_scaled[i].clone())?;
					ctx.next();
					let s = ctx.copy_assign(config.temp, s[i].clone())?;
					ctx.next();
					ctx.constrain_equal(passed_s, s)?;
				}
				Ok(())
			},
		)?;

		Ok(())
	}
}

/// Native version of EigenTrust algorithm
pub fn native<F: FieldExt, const N: usize, const I: usize, const S: u128>(
	mut s: [F; N], ops: [[F; N]; N],
) -> [F; N] {
	for _ in 0..I {
		let mut distributions: [[F; N]; N] = [[F::zero(); N]; N];
		for j in 0..N {
			distributions[j] = ops[j].map(|v| v * s[j]);
		}

		let mut new_s: [F; N] = [F::zero(); N];
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
	};
	use halo2::{dev::MockProver, halo2curves::bn256::Bn256};
	use rand::thread_rng;

	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;

	#[test]
	fn test_closed_graph_circut() {
		let s: [Scalar; NUM_NEIGHBOURS] = [Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
		let ops = [
			[0, 200, 300, 500, 0],
			[100, 0, 100, 100, 700],
			[400, 100, 0, 200, 300],
			[100, 100, 700, 0, 100],
			[300, 100, 400, 200, 0],
		]
		.map(|arr| arr.map(|x| Scalar::from_u128(x)));
		let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops);

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages = ops.map(|scores| {
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
		});

		let signatures = secret_keys
			.zip(pub_keys.clone())
			.zip(messages)
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg));

		let k = 13;
		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys, signatures, ops, messages,
		);

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
		let s: [Scalar; NUM_NEIGHBOURS] = [Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
		let ops = [
			[0, 200, 300, 500, 0],
			[100, 0, 100, 100, 700],
			[400, 100, 0, 200, 300],
			[100, 100, 700, 0, 100],
			[300, 100, 400, 200, 0],
		]
		.map(|arr| arr.map(|x| Scalar::from_u128(x)));
		let res = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops);

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages = ops.map(|scores| {
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
		});

		let signatures = secret_keys
			.zip(pub_keys.clone())
			.zip(messages)
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg));

		let k = 13;
		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys, signatures, ops, messages,
		);

		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, et, &[&res], rng).unwrap();
		assert!(res);
	}
}
