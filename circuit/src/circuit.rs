use crate::{
	eddsa::{
		native::{PublicKey, Signature},
		EddsaChip, EddsaConfig,
	},
	edwards::params::{BabyJubJub, EdwardsParams},
	gadgets::{bits2num::to_bits, lt_eq::N_SHIFTED},
	params::{poseidon_bn254_5x5::Params, RoundParams},
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::{PoseidonSpongeChip, PoseidonSpongeConfig},
		PoseidonChip,
	},
	CommonConfig, PoseidonConfig,
};
use halo2wrong::{
	curves::{bn256::Fr as Scalar, FieldExt},
	halo2::{
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
	},
	RegionCtx,
};
use maingate::{MainGate, MainGateConfig};
use std::marker::PhantomData;

const NUM_ITER: usize = 20;
const NUM_NEIGHBOURS: usize = 5;
const INITIAL_SCORE: f32 = 1000.;
const SCALE: f32 = 100000000.;

type PoseidonNativeHasher = Poseidon<Scalar, 5, Params>;
type PoseidonHasher = PoseidonChip<Scalar, 5, Params>;
type SpongeHasher = PoseidonSpongeChip<Scalar, 5, Params>;
type Eddsa = EddsaChip<Scalar, BabyJubJub, Params>;

/// The columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	maingate: MainGateConfig,
	eddsa: EddsaConfig,
	sponge: PoseidonSpongeConfig<5>,
	temp: Column<Advice>,
	fixed: Column<Fixed>,
	pub_ins: Column<Instance>,
}

struct EigenTrust {
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

impl EigenTrust {
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
}

impl Circuit<Scalar> for EigenTrust {
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
		let maingate = MainGate::configure(meta);
		let eddsa = Eddsa::configure(meta);
		let sponge = SpongeHasher::configure(meta);
		let temp = meta.advice_column();
		let fixed = meta.fixed_column();
		let pub_ins = meta.instance_column();

		EigenTrustConfig { maingate, eddsa, sponge, temp, fixed, pub_ins }
	}

	fn synthesize(
		&self, config: EigenTrustConfig, mut layouter: impl Layouter<Scalar>,
	) -> Result<(), Error> {
		let (zero, pk_x, pk_y, big_r_x, big_r_y, s, ops) = layouter.assign_region(
			|| "temp",
			|mut region: Region<'_, Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_fixed(|| "zero", config.fixed, Scalar::zero())?;
				ctx.next();
				let assigned_pk_x =
					self.pk_x.try_map(|v| ctx.assign_advice(|| "pk_x", config.temp, v))?;
				ctx.next();
				let assigned_pk_y =
					self.pk_y.try_map(|v| ctx.assign_advice(|| "pk_y", config.temp, v))?;
				ctx.next();
				let assigned_big_r_x =
					self.big_r_x.try_map(|v| ctx.assign_advice(|| "big_r_x", config.temp, v))?;
				ctx.next();
				let assigned_big_r_y =
					self.big_r_y.try_map(|v| ctx.assign_advice(|| "big_r_y", config.temp, v))?;
				ctx.next();
				let assigned_s = self.s.try_map(|v| ctx.assign_advice(|| "s", config.temp, v))?;
				ctx.next();

				let assigned_ops = self.ops.try_map(|vs| {
					vs.try_map(|v| {
						let val = ctx.assign_advice(|| "op", config.temp, v);
						ctx.next();
						val
					})
				})?;

				Ok((
					zero, assigned_pk_x, assigned_pk_y, assigned_big_r_x, assigned_big_r_y,
					assigned_s, assigned_ops,
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
			scores_sponge.update(&pk_x);
			scores_sponge.update(&pk_y);
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
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::eddsa::native::{sign, SecretKey};
	use rand::thread_rng;

	type PoseidonNativeSponge = PoseidonSponge<Scalar, 5, Params>;

	fn native(
		mut s: [f32; NUM_NEIGHBOURS], ops: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS],
	) -> [f32; NUM_NEIGHBOURS] {
		for _ in 0..NUM_ITER {
			let mut distributions: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] =
				[[0.; NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
			for j in 0..NUM_NEIGHBOURS {
				distributions[j] = ops[j].map(|v| v * s[j]);
			}

			let mut new_s: [f32; NUM_NEIGHBOURS] = [0.; NUM_NEIGHBOURS];
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					new_s[i] += distributions[j][i];
				}
			}

			s = new_s;

			println!("[{}]", s.map(|v| format!("{:>9.4}", v)).join(", "));
		}

		s
	}

	#[test]
	fn test_closed_graph_native() {
		let s: [f32; NUM_NEIGHBOURS] = [INITIAL_SCORE; NUM_NEIGHBOURS];
		let ops = [
			[0.0, 0.2, 0.3, 0.5, 0.0],
			[0.1, 0.0, 0.1, 0.1, 0.7],
			[0.4, 0.1, 0.0, 0.2, 0.3],
			[0.1, 0.1, 0.7, 0.0, 0.1],
			[0.3, 0.1, 0.4, 0.2, 0.0],
		];
		let res = native(s, ops);

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.x);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let ops_scaled = ops.map(|vals| vals.map(|x| Scalar::from((x * SCALE) as u64)));
		let messages = ops_scaled.map(|scores| {
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

		let et = EigenTrust::new(pub_keys, signatures, ops_scaled, messages);
	}
}
