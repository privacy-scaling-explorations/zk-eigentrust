#![feature(array_try_map)]

mod ecdsa;
mod poseidon;
mod utils;

use crate::ecdsa::SigData;
use ::ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use ecc::{maingate::RegionCtx, EccConfig, GeneralEccChip};
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
use poseidon::{params::RoundParams, wrong::PoseidonChip};
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
pub struct EigenTrustCircuit<E: CurveAffine, N: FieldExt, const SIZE: usize, P: RoundParams<N, 5>> {
	op_v: Option<N>,
	pubkey_v: Option<E>,
	c_v: [Option<N>; SIZE],
	pubkeys_v: [Option<E>; SIZE],
	pubkey_i: Option<E>,
	sig_i: Option<SigData<E::ScalarExt>>,
	m_hash: Option<E::ScalarExt>,
	opinions: [Option<N>; SIZE],
	aux_generator: Option<E>,
	window_size: usize,
	_marker: PhantomData<N>,
	_params: PhantomData<P>,
}

impl<E: CurveAffine, N: FieldExt, const SIZE: usize, P: RoundParams<N, 5>>
	EigenTrustCircuit<E, N, SIZE, P>
{
	pub fn new(
		op_v: Option<N>,
		pubkey_v: Option<E>,
		c_v: [Option<N>; SIZE],
		pubkeys_v: [Option<E>; SIZE],
		pubkey_i: Option<E>,
		sig_i: Option<SigData<E::ScalarExt>>,
		m_hash: Option<E::ScalarExt>,
		opinions: [Option<N>; SIZE],
		aux_generator: Option<E>,
	) -> Self {
		Self {
			op_v,
			pubkey_v,
			c_v,
			pubkeys_v,
			pubkey_i,
			sig_i,
			m_hash,
			opinions,
			aux_generator,
			window_size: 2,
			_marker: PhantomData,
			_params: PhantomData,
		}
	}
}

impl<E: CurveAffine, N: FieldExt, const SIZE: usize, P: RoundParams<N, 5>> Circuit<N>
	for EigenTrustCircuit<E, N, SIZE, P>
{
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			op_v: None,
			pubkey_v: None,
			c_v: [None; SIZE],
			pubkeys_v: [None; SIZE],
			pubkey_i: None,
			sig_i: None,
			m_hash: None,
			opinions: [None; SIZE],
			aux_generator: None,
			window_size: self.window_size,
			_marker: PhantomData,
			_params: PhantomData,
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
		let main_gate = MainGate::new(config.main_gate_config.clone());

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

		let t_i = layouter.assign_region(
			|| "t_i",
			|mut region| {
				let position = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, position);
				let unassigned_ops = self.opinions.clone().map(|val| UnassignedValue::from(val));
				let assigned_ops =
					unassigned_ops.map(|val| main_gate.assign_value(ctx, &val).unwrap());

				let mut sum = main_gate.assign_constant(ctx, N::zero())?;
				for i in 0..SIZE {
					sum = main_gate.add(ctx, &sum, &assigned_ops[i])?;
				}

				Ok(sum)
			},
		)?;

		let c_v = layouter.assign_region(
			|| "c_v",
			|mut region| {
				let position = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, position);
				let assigned_pks = self
					.pubkeys_v
					.try_map(|pk| ecc_chip.assign_point(ctx, pk.into()))?;
				let assigned_pk_v = ecc_chip.assign_point(ctx, self.pubkey_v)?;
				let unassigned_c_v = self.c_v.map(|val| UnassignedValue::from(val));
				let assigned_c_v = unassigned_c_v.try_map(|c| main_gate.assign_value(ctx, &c))?;

				let mut final_c_v = main_gate.assign_constant(ctx, N::zero())?;
				for i in 0..SIZE {
					let pk = &assigned_pks[i];
					let is_eq_x = main_gate.is_equal(
						ctx,
						&pk.get_x().native(),
						&assigned_pk_v.get_x().native(),
					)?;
					let is_eq_y = main_gate.is_equal(
						ctx,
						&pk.get_y().native(),
						&assigned_pk_v.get_y().native(),
					)?;
					let is_eq = main_gate.and(ctx, &is_eq_x, &is_eq_y)?;
					let product = main_gate.mul(ctx, &is_eq.into(), &assigned_c_v[i])?;
					final_c_v = main_gate.add(ctx, &final_c_v, &product)?;
				}

				Ok(final_c_v)
			},
		)?;

		let opv = layouter.assign_region(
			|| "op_v",
			|mut region| {
				let position = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, position);

				let unassigned_opv = UnassignedValue::from(self.op_v);
				let assigned_opv = main_gate.assign_value(ctx, &unassigned_opv)?;
				let res = main_gate.mul(ctx, &t_i, &c_v)?;
				main_gate.assert_equal(ctx, &assigned_opv, &res)?;

				Ok(res)
			},
		)?;

		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		layouter.assign_region(
			|| "sig_i_verify",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let integer_r = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.r));
				let integer_s = ecc_chip.new_unassigned_scalar(self.sig_i.map(|s| s.s));
				let unassigned_m_hash = ecc_chip.new_unassigned_scalar(self.m_hash);

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
				let m_hash = scalar_chip.assign_integer(ctx, unassigned_m_hash, Range::Remainder)?;
				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pubkey_i.map(|p| p.into()))?;

				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};

				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &m_hash)?;

				Ok(())
			},
		)?;

		config.config_range(&mut layouter)?;

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
			group::{Curve, Group},
			secp256k1::{Fq, Secp256k1Affine as Secp256},
		},
		halo2::arithmetic::CurveAffine,
	};
	use maingate::halo2::dev::MockProver;
	use rand::thread_rng;
	use utils::prove_and_verify;

	const SIZE: usize = 3;

	#[test]
	fn test_eigen_trust_verify() {
		let k = 18;
		let mut rng = thread_rng();

		let pairs = [(); SIZE].map(|_| Keypair::<Secp256>::new(&mut rng));

		// Data for Verifier
		let op_v = Some(Fr::from_u128(3));
		let pair_v = pairs[0];
		let pubkey_v = Some(pair_v.public_key().clone());

		// Epoch
		let epoch = Fr::from_u128(3801);

		// Data for prover
		let pair_i = Keypair::<Secp256>::new(&mut rng);
		let pubkey_i = Some(pair_i.public_key().clone());
		let zero = Fr::zero();
		let inputs = [zero, epoch, op_v.unwrap(), zero, zero];
		let poseidon = Poseidon::<Fr, 5, Params5x5Bn254>::new(inputs);
		let out = poseidon.permute()[0];
		let m_hash = Some(Fq::from_bytes(&out.to_bytes()).unwrap());
		let sig_i = Some(generate_signature(pair_i, m_hash.unwrap(), &mut rng).unwrap());

		// Data from neighbors of i
		let opinions = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let pubkeys = pairs.map(|p| Some(p.public_key().clone()));
		let c_v = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];

		// Aux generator
		let aux_generator = Some(<Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine());

		let eigen_trust = EigenTrustCircuit::<_, _, 3, Params5x5Bn254>::new(
			op_v,
			pubkey_v,
			c_v,
			pubkeys,
			pubkey_i,
			sig_i,
			m_hash,
			opinions,
			aux_generator,
		);

		let public_inputs = vec![vec![]];
		let prover = match MockProver::<Fr>::run(k, &eigen_trust, public_inputs) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eigen_trust_production_prove_verify() {
		let k = 18;
		let mut rng = thread_rng();

		let pairs = [(); SIZE].map(|_| Keypair::<Secp256>::new(&mut rng));

		// Data for Verifier
		let op_v = Some(Fr::from_u128(3));
		let pair_v = pairs[0];
		let pubkey_v = Some(pair_v.public_key().clone());

		// Epoch
		let epoch = Fr::from_u128(3801);

		// Data for prover
		let pair_i = Keypair::<Secp256>::new(&mut rng);
		let pubkey_i = Some(pair_i.public_key().clone());
		let zero = Fr::zero();
		let inputs = [zero, epoch, op_v.unwrap(), zero, zero];
		let poseidon = Poseidon::<Fr, 5, Params5x5Bn254>::new(inputs);
		let out = poseidon.permute()[0];
		let m_hash = Some(Fq::from_bytes(&out.to_bytes()).unwrap());
		let sig_i = Some(generate_signature(pair_i, m_hash.unwrap(), &mut rng).unwrap());

		// Data from neighbors of i
		let opinions = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];
		let pubkeys = pairs.map(|p| Some(p.public_key().clone()));
		let c_v = [
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
			Some(Fr::from_u128(1)),
		];

		// Aux generator
		let aux_generator = Some(<Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine());

		let eigen_trust = EigenTrustCircuit::<_, _, 3, Params5x5Bn254>::new(
			op_v,
			pubkey_v,
			c_v,
			pubkeys,
			pubkey_i,
			sig_i,
			m_hash,
			opinions,
			aux_generator,
		);

		prove_and_verify::<Bn256, _, _>(k, eigen_trust, &mut rng).unwrap();
	}
}
