#![feature(array_try_map)]

pub mod ecdsa;
mod poseidon;
pub mod utils;

use crate::ecdsa::SigData;
use ::ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use ecc::{maingate::RegionCtx, EccConfig, GeneralEccChip};
pub use halo2wrong;
use halo2wrong::halo2::{
	arithmetic::{CurveAffine, FieldExt},
	circuit::{Layouter, SimpleFloorPlanner},
	plonk::{Circuit, ConstraintSystem, Error},
};
use integer::{IntegerInstructions, Range, NUMBER_OF_LOOKUP_LIMBS};
use maingate::{
	MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
	UnassignedValue,
};
use std::marker::PhantomData;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	main_gate_config: MainGateConfig,
	range_config: RangeConfig,
}

impl EigenTrustConfig {
	pub fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
		let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
		let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
		range_chip.load_limb_range_table(layouter)?;
		range_chip.load_overflow_range_tables(layouter)?;

		Ok(())
	}
}

#[derive(Clone)]
pub struct EigenTrustCircuit<E: CurveAffine, N: FieldExt, const SIZE: usize> {
	pubkey_i: Option<E>,
	sig_i: Option<SigData<E::ScalarExt>>,
	t_i: Option<N>,
	c_ji: [Option<N>; SIZE],
	t_j: [Option<N>; SIZE],
	neighbor_pubkeys: [Option<E>; SIZE],
	neighbor_sigs: [Option<SigData<E::ScalarExt>>; SIZE],

	aux_generator: Option<E>,
	window_size: usize,
	_marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt, const SIZE: usize> EigenTrustCircuit<E, N, SIZE> {
	pub fn new(
		pubkey_i: Option<E>,
		sig_i: Option<SigData<E::ScalarExt>>,
		t_i: Option<N>,
		c_ji: [Option<N>; SIZE],
		t_j: [Option<N>; SIZE],
		neighbor_pubkeys: [Option<E>; SIZE],
		neighbor_sigs: [Option<SigData<E::ScalarExt>>; SIZE],
		aux_generator: Option<E>,
	) -> Self {
		Self {
			pubkey_i,
			sig_i,
			t_i,
			c_ji,
			t_j,
			neighbor_pubkeys,
			neighbor_sigs,

			aux_generator,
			window_size: 2,
			_marker: PhantomData,
		}
	}
}

impl<E: CurveAffine, N: FieldExt, const SIZE: usize> Circuit<N> for EigenTrustCircuit<E, N, SIZE> {
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pubkey_i: None,
			sig_i: None,
			t_i: None,
			c_ji: [None; SIZE],
			t_j: [None; SIZE],
			neighbor_pubkeys: [None; SIZE],
			neighbor_sigs: [None; SIZE],

			aux_generator: None,
			window_size: self.window_size,
			_marker: PhantomData,
		}
	}

	fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		let (rns_base, rns_scalar) = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
		let main_gate_config = MainGate::<N>::configure(meta);
		let mut overflow_bit_lengths: Vec<usize> = vec![];
		overflow_bit_lengths.extend(rns_base.overflow_lengths());
		overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
		let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
		EigenTrustConfig {
			main_gate_config,
			range_config,
		}
	}

	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<N>,
	) -> Result<(), Error> {
		let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
			EccConfig::new(config.range_config.clone(), config.main_gate_config.clone()),
		);
		let scalar_chip = ecc_chip.scalar_field_chip();
		let main_gate = MainGate::<N>::new(config.main_gate_config.clone());

		layouter.assign_region(
			|| "assign_aux",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				ecc_chip.assign_aux_generator(ctx, self.aux_generator)?;
				ecc_chip.assign_aux(ctx, self.window_size, 1)?;
				Ok(())
			},
		)?;

		let (t_i, c_jis, t_js) = layouter.assign_region(
			|| "t_i",
			|mut region| {
				let position = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, position);
				let unassigned_c_jis = self.c_ji.clone().map(|val| UnassignedValue::from(val));
				let unassigned_t_js = self.c_ji.clone().map(|val| UnassignedValue::from(val));
				let assigned_c_jis =
					unassigned_c_jis.map(|val| main_gate.assign_value(ctx, &val).unwrap());
				let assigned_t_js =
					unassigned_t_js.map(|val| main_gate.assign_value(ctx, &val).unwrap());

				let mut sum = main_gate.assign_constant(ctx, N::zero())?;
				for i in 0..SIZE {
					let product = main_gate.mul(ctx, &assigned_c_jis[i], &assigned_t_js[i])?;
					sum = main_gate.add(ctx, &sum, &product)?;
				}

				Ok((sum, assigned_c_jis, assigned_t_js))
			},
		)?;

		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		let (r, s, m_hash, pk) = layouter.assign_region(
			|| "sig_i_verify",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let unassigned_r = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.r));
				let unassigned_s = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.s));
				let unassigned_m_hash =
					ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.m_hash));

				let assigned_r = scalar_chip.assign_integer(ctx, unassigned_r, Range::Remainder)?;
				let assigned_s = scalar_chip.assign_integer(ctx, unassigned_s, Range::Remainder)?;
				let assigned_m_hash =
					scalar_chip.assign_integer(ctx, unassigned_m_hash, Range::Remainder)?;
				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pubkey_i.map(|p| p.into()))?;

				let sig = AssignedEcdsaSig {
					r: assigned_r.clone(),
					s: assigned_s.clone(),
				};
				let assigned_pk = AssignedPublicKey {
					point: pk_in_circuit.clone(),
				};

				ecdsa_chip.verify(ctx, &sig, &assigned_pk, &assigned_m_hash)?;

				Ok((assigned_r, assigned_s, assigned_m_hash, pk_in_circuit))
			},
		)?;

		// layouter.assign_region(
		// 	|| "sigs_j_verify",
		// 	|mut region| {
		// 		let offset = &mut 0;
		// 		let ctx = &mut RegionCtx::new(&mut region, offset);

		// 		for i in 0..SIZE {
		// 			let unassigned_r =
		// ecc_chip.new_unassigned_scalar(self.neighbor_sigs[i].map(|s| s.r));
		// 			let unassigned_s =
		// ecc_chip.new_unassigned_scalar(self.neighbor_sigs[i].map(|s| s.s));
		// 			let unassigned_m_hash =
		// ecc_chip.new_unassigned_scalar(self.neighbor_sigs[i].map(|s| s.m_hash));

		// 			let assigned_r = scalar_chip.assign_integer(ctx, unassigned_r,
		// Range::Remainder)?; 			let assigned_s = scalar_chip.assign_integer(ctx,
		// unassigned_s, Range::Remainder)?; 			let assigned_m_hash =
		// 				scalar_chip.assign_integer(ctx, unassigned_m_hash, Range::Remainder)?;
		// 			let pk_in_circuit = ecc_chip.assign_point(ctx,
		// self.neighbor_pubkeys[i].map(|p| p.into()))?;

		// 			let sig = AssignedEcdsaSig {
		// 				r: assigned_r,
		// 				s: assigned_s,
		// 			};
		// 			let assigned_pk = AssignedPublicKey {
		// 				point: pk_in_circuit,
		// 			};

		// 			ecdsa_chip.verify(ctx, &sig, &assigned_pk, &assigned_m_hash)?;
		// 		}

		// 		Ok(())
		// 	},
		// )?;

		config.config_range(&mut layouter)?;

		main_gate.expose_public(layouter.namespace(|| "pk_x"), pk.get_x().native(), 0);
		main_gate.expose_public(layouter.namespace(|| "pk_y"), pk.get_y().native(), 1);
		main_gate.expose_public(layouter.namespace(|| "r"), r.native(), 2);
		main_gate.expose_public(layouter.namespace(|| "s"), s.native(), 3);
		main_gate.expose_public(layouter.namespace(|| "m_hash"), m_hash.native(), 4);

		let mut offset = 5;
		for i in 0..SIZE {
			main_gate.expose_public(layouter.namespace(|| "c_ji"), c_jis[i], offset);
			offset += 1;
		}

		for i in 0..SIZE {
			main_gate.expose_public(layouter.namespace(|| "t_j"), t_js[i], offset);
			offset += 1;
		}

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ecdsa::native::{generate_signature, Keypair},
		poseidon::{native::Poseidon, params::Params5x5Bn254},
	};
	use halo2wrong::{
		curves::{
			bn256::{Bn256, Fr},
			group::{ff::PrimeField, Curve, Group},
			secp256k1::{Fq, Secp256k1Affine as Secp256},
		},
		halo2::arithmetic::CurveAffine,
	};
	use maingate::halo2::dev::MockProver;
	use rand::thread_rng;
	use utils::{generate_params, prove_and_verify};

	const SIZE: usize = 3;

	fn to_wide(p: [u8; 32]) -> [u8; 64] {
		let mut res = [0u8; 64];
		res[..32].copy_from_slice(&p[..]);
		res
	}

	#[test]
	fn test_eigen_trust_verify() {
		let k = 18;
		let mut rng = thread_rng();

		let m_hash = Some(Fq::from_u128(12342));

		// Data for prover
		let pair_i = Keypair::<Secp256>::new(&mut rng);
		let pubkey_i = Some(pair_i.public().clone());
		let sig_i = Some(generate_signature(pair_i, m_hash.unwrap(), &mut rng).unwrap());
		let t_i = Some(Fr::from_u128(3));

		// Data from neighbors of i
		let c_ji = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let t_j = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let pairs = [(); SIZE].map(|_| Keypair::<Secp256>::new(&mut rng));
		let pubkeys = pairs.map(|p| Some(p.public().clone()));
		let sigs = pairs.map(|p| Some(generate_signature(p, m_hash.unwrap(), &mut rng).unwrap()));

		// Aux generator
		let aux_generator = Some(<Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine());

		let eigen_trust = EigenTrustCircuit::<_, _, 3>::new(
			pubkey_i,
			sig_i,
			t_i,
			c_ji,
			t_j,
			pubkeys,
			sigs,
			aux_generator,
		);

		let pk_ix = Fr::from_bytes_wide(&to_wide(pubkey_i.unwrap().x.to_bytes()));
		let pk_iy = Fr::from_bytes_wide(&to_wide(pubkey_i.unwrap().y.to_bytes()));
		let r = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().r.to_bytes()));
		let s = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().s.to_bytes()));
		let m_hash = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().m_hash.to_bytes()));

		let mut pub_ins = Vec::new();
		pub_ins.push(pk_ix);
		pub_ins.push(pk_iy);
		pub_ins.push(r);
		pub_ins.push(s);
		pub_ins.push(m_hash);

		for i in 0..SIZE {
			pub_ins.push(c_ji[i].unwrap());
		}

		for i in 0..SIZE {
			pub_ins.push(t_j[i].unwrap());
		}

		let prover = match MockProver::<Fr>::run(k, &eigen_trust, vec![pub_ins]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eigen_trust_production_prove_verify() {
		let k = 18;
		let mut rng = thread_rng();

		let m_hash = Some(Fq::from_u128(12342));

		// Data for prover
		let pair_i = Keypair::<Secp256>::new(&mut rng);
		let pubkey_i = Some(pair_i.public().clone());
		let sig_i = Some(generate_signature(pair_i, m_hash.unwrap(), &mut rng).unwrap());
		let t_i = Some(Fr::from_u128(3));

		// Data from neighbors of i
		let c_ji = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let t_j = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let pairs = [(); SIZE].map(|_| Keypair::<Secp256>::new(&mut rng));
		let pubkeys = pairs.map(|p| Some(p.public().clone()));
		let sigs = pairs.map(|p| Some(generate_signature(p, m_hash.unwrap(), &mut rng).unwrap()));

		// Aux generator
		let aux_generator = Some(<Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine());

		let eigen_trust = EigenTrustCircuit::<_, _, 3>::new(
			pubkey_i,
			sig_i,
			t_i,
			c_ji,
			t_j,
			pubkeys,
			sigs,
			aux_generator,
		);

		let pk_ix = Fr::from_bytes_wide(&to_wide(pubkey_i.unwrap().x.to_bytes()));
		let pk_iy = Fr::from_bytes_wide(&to_wide(pubkey_i.unwrap().y.to_bytes()));
		let r = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().r.to_bytes()));
		let s = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().s.to_bytes()));
		let m_hash = Fr::from_bytes_wide(&to_wide(sig_i.unwrap().m_hash.to_bytes()));

		let mut pub_ins = Vec::new();
		pub_ins.push(pk_ix);
		pub_ins.push(pk_iy);
		pub_ins.push(r);
		pub_ins.push(s);
		pub_ins.push(m_hash);

		for i in 0..SIZE {
			pub_ins.push(c_ji[i].unwrap());
		}

		for i in 0..SIZE {
			pub_ins.push(t_j[i].unwrap());
		}

		let params = generate_params(k);
		prove_and_verify::<Bn256, _, _>(params, eigen_trust, &[&pub_ins[..]], &mut rng).unwrap();
	}
}
