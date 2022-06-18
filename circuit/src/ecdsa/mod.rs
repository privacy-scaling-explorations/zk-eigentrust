use ecc::{maingate::RegionCtx, EccConfig, GeneralEccChip};
use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use halo2wrong::halo2::{
	arithmetic::{CurveAffine, FieldExt},
	circuit::{Layouter, SimpleFloorPlanner},
	plonk::{Circuit, ConstraintSystem, Error},
};
use integer::{IntegerInstructions, Range, NUMBER_OF_LOOKUP_LIMBS};
use maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions};

use std::marker::PhantomData;

pub use self::native::SigData;

pub mod native;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;

#[derive(Clone, Debug)]
pub struct EcdsaVerifierConfig {
	main_gate_config: MainGateConfig,
	range_config: RangeConfig,
}

impl EcdsaVerifierConfig {
	pub fn config_range<N: FieldExt>(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
		let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
		let range_chip = RangeChip::<N>::new(self.range_config.clone(), bit_len_lookup);
		range_chip.load_limb_range_table(layouter)?;
		range_chip.load_overflow_range_tables(layouter)?;

		Ok(())
	}
}

#[derive(Default, Clone)]
pub struct EcdsaVerifier<E: CurveAffine, N: FieldExt> {
	sig_data: Option<SigData<E::ScalarExt>>,
	pk: Option<E>,
	m_hash: Option<E::ScalarExt>,
	aux_generator: Option<E>,
	window_size: usize,
	_marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt> EcdsaVerifier<E, N> {
	pub fn new(
		sig_data: Option<SigData<E::ScalarExt>>,
		pk: Option<E>,
		m_hash: Option<E::ScalarExt>,
		aux_generator: Option<E>,
	) -> Self {
		Self {
			sig_data,
			pk,
			m_hash,
			aux_generator,
			window_size: 2,
			_marker: PhantomData,
		}
	}
}

impl<E: CurveAffine, N: FieldExt> Circuit<N> for EcdsaVerifier<E, N> {
	type Config = EcdsaVerifierConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self::default()
	}

	fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		let (rns_base, rns_scalar) = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
		let main_gate_config = MainGate::<N>::configure(meta);
		let mut overflow_bit_lengths: Vec<usize> = vec![];
		overflow_bit_lengths.extend(rns_base.overflow_lengths());
		overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
		let range_config = RangeChip::<N>::configure(meta, &main_gate_config, overflow_bit_lengths);
		EcdsaVerifierConfig {
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

		let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

		layouter.assign_region(
			|| "region 0",
			|mut region| {
				let offset = &mut 0;
				let ctx = &mut RegionCtx::new(&mut region, offset);

				let integer_r = ecc_chip.new_unassigned_scalar(self.sig_data.map(|s| s.r));
				let integer_s = ecc_chip.new_unassigned_scalar(self.sig_data.map(|s| s.s));
				let msg_hash = ecc_chip.new_unassigned_scalar(self.m_hash);

				let r_assigned = scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
				let s_assigned = scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
				let sig = AssignedEcdsaSig {
					r: r_assigned,
					s: s_assigned,
				};

				let pk_in_circuit = ecc_chip.assign_point(ctx, self.pk.map(|p| p.into()))?;
				let pk_assigned = AssignedPublicKey {
					point: pk_in_circuit,
				};
				let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
				ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
			},
		)?;

		config.config_range(&mut layouter)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::ecdsa::native::Keypair;

	use super::{native::generate_signature, *};
	use halo2wrong::{
		curves::{
			bn256::Fr,
			group::{Curve, Group},
			secp256k1::Secp256k1Affine as Secp256,
		},
		halo2::arithmetic::CurveAffine,
	};
	use maingate::halo2::dev::MockProver;
	use rand::thread_rng;

	#[test]
	fn test_ecdsa_verify() {
		let k = 20;
		let mut rng = thread_rng();

		let pair = Keypair::<Secp256>::new(&mut rng);
		let pk = pair.public().clone();
		let m_hash = <Secp256 as CurveAffine>::ScalarExt::from(4);
		let sig_data = generate_signature::<Secp256, _>(pair, m_hash, &mut rng).unwrap();

		let aux_generator = <Secp256 as CurveAffine>::CurveExt::random(&mut rng).to_affine();
		let sig_verifyer = EcdsaVerifier {
			sig_data: Some(sig_data),
			pk: Some(pk),
			m_hash: Some(m_hash),
			aux_generator: Some(aux_generator),
			window_size: 2,
			_marker: PhantomData,
		};
		let public_inputs = vec![vec![]];
		let prover = match MockProver::<Fr>::run(k, &sig_verifyer, public_inputs) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};
		assert_eq!(prover.verify(), Ok(()));
	}
}
