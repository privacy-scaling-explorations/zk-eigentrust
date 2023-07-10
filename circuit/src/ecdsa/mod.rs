/// Native version of Ecdsa
pub mod native;

use crate::ecc::generic::{AssignedAux, EccAddChipset};
use crate::ecc::EccAddConfig;
use crate::params::ecc::EccParams;
use crate::{
	ecc::{
		generic::{AssignedPoint, EccMulChipset},
		EccMulConfig,
	},
	integer::{AssignedInteger, IntegerMulChip},
	params::rns::RnsParams,
	Chipset, CommonConfig, FieldExt,
};
use crate::{Chip, RegionCtx};
use halo2::circuit::Region;
use halo2::{
	circuit::Layouter,
	halo2curves::CurveAffine,
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
/// Configuration structure for the Ecdsa
pub struct EcdsaConfig {
	// ECC scalar multiplication configuration
	ecc_mul_scalar: EccMulConfig,
	// ECC addition configuration
	ecc_add: EccAddConfig,
	// Integer multiplication selector
	integer_mul_selector: Selector,
}

impl EcdsaConfig {
	/// Construct a new Ecdsa config
	pub fn new(ecc_mul_scalar: EccMulConfig, integer_mul_selector: Selector) -> Self {
		Self { ecc_add: ecc_mul_scalar.add.clone(), ecc_mul_scalar, integer_mul_selector }
	}
}

/// Ecdsa Chipset structure
pub struct EcdsaChipset<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Public key
	public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Generator as a ec point
	g_as_ecpoint: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature
	signature: (
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	),
	// Message hash
	msg_hash: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature inverse
	s_inv: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	// Aux for to_add and to_sub
	aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	_p: PhantomData<(P, EC)>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new chipset.
	pub fn new(
		public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		g_as_ecpoint: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		signature: (
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		),
		msg_hash: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		Self { public_key, g_as_ecpoint, signature, msg_hash, s_inv, aux, _p: PhantomData }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> Chipset<N>
	for EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	type Config = EcdsaConfig;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let (r, _) = &self.signature;

		let u_1_chip = IntegerMulChip::new(self.msg_hash, self.s_inv.clone());
		let u_1 = u_1_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "u_1"),
		)?;

		let u_2_chip = IntegerMulChip::new(r.clone(), self.s_inv);
		let u_2 = u_2_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "u_2"),
		)?;

		let v_1_ecc_mul_scalar_chip = EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			self.g_as_ecpoint,
			u_1,
			self.aux.clone(),
		);
		let v_1 = v_1_ecc_mul_scalar_chip.synthesize(
			common,
			&config.ecc_mul_scalar,
			layouter.namespace(|| "v_1"),
		)?;

		let v_2_ecc_mul_scalar_chip =
			EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(self.public_key, u_2, self.aux);
		let v_2 = v_2_ecc_mul_scalar_chip.synthesize(
			common,
			&config.ecc_mul_scalar,
			layouter.namespace(|| "v_2"),
		)?;

		let r_point_add_chip = EccAddChipset::<C, N, NUM_LIMBS, NUM_BITS, P>::new(v_1, v_2);
		let r_point = r_point_add_chip.synthesize(
			common,
			&config.ecc_add,
			layouter.namespace(|| "r_point"),
		)?;

		let x_candidate = r_point.x;
		layouter.assign_region(
			|| "enforce_equal",
			|region: Region<'_, N>| {
				let mut region_ctx = RegionCtx::new(region, 0);
				for i in 0..NUM_LIMBS {
					region_ctx.constrain_equal(x_candidate.limbs[i].clone(), r.limbs[i].clone())?;
				}
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::{EcdsaChipset, EcdsaConfig};
	use crate::ecc::generic::{AuxAssigner, PointAssigner};
	use crate::ecc::AuxConfig;
	use crate::ecdsa::native::EcdsaKeypair;
	use crate::integer::IntegerAssigner;
	use crate::params::ecc::secp256k1::Secp256k1Params;
	use crate::params::rns::secp256k1::Secp256k1_4_68;
	use crate::utils::big_to_fe;
	use crate::UnassignedValue;
	use crate::{
		ecc::{
			generic::{native::EcPoint, UnassignedEcPoint},
			EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
			EccUnreducedLadderConfig,
		},
		gadgets::{
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			native::Integer, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
			IntegerSubChip, UnassignedInteger,
		},
		Chip, Chipset, CommonConfig,
	};
	use halo2::arithmetic::Field;
	use halo2::dev::MockProver;
	use halo2::halo2curves::ff::PrimeField;
	use halo2::halo2curves::group::Curve;
	use halo2::halo2curves::secp256k1::Secp256k1;
	use halo2::{
		circuit::{Layouter, SimpleFloorPlanner},
		halo2curves::{
			bn256::Fr,
			secp256k1::{Fp, Fq, Secp256k1Affine},
		},
		plonk::{Circuit, ConstraintSystem, Error},
	};

	type W = Fp;
	type SecpScalar = Fq;
	type N = Fr;
	type C = Secp256k1Affine;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		ecdsa: EcdsaConfig,
		aux: AuxConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<N>) -> Self {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));
			let bits2num_selector = Bits2NumChip::configure(&common, meta);

			let integer_reduce_selector =
				IntegerReduceChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_add_selector =
				IntegerAddChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_sub_selector =
				IntegerSubChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_mul_selector =
				IntegerMulChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_div_selector =
				IntegerDivChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_mul_selector_secp_scalar =
				IntegerMulChip::<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let ecc_add = EccAddConfig::new(
				integer_reduce_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_double = EccDoubleConfig::new(
				integer_reduce_selector, integer_add_selector, integer_sub_selector,
				integer_mul_selector, integer_div_selector,
			);

			let ecc_ladder = EccUnreducedLadderConfig::new(
				integer_add_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_table_select = EccTableSelectConfig::new(main);

			let ecc_mul_scalar = EccMulConfig::new(
				ecc_ladder.clone(),
				ecc_add.clone(),
				ecc_double.clone(),
				ecc_table_select,
				bits2num_selector.clone(),
			);

			let ecdsa = EcdsaConfig::new(ecc_mul_scalar, integer_mul_selector_secp_scalar);

			let aux = AuxConfig::new(ecc_double);

			TestConfig { common, ecdsa, aux }
		}
	}

	#[derive(Clone)]
	struct TestEcdsaCircuit {
		public_key: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		signature: (
			UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
			UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
		),
		msg_hash: UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl TestEcdsaCircuit {
		fn new(
			public_key: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			g_as_ecpoint: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			signature: (
				Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
				Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
			),
			msg_hash: Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
			s_inv: Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self {
				public_key: UnassignedEcPoint::from(public_key),
				g_as_ecpoint: UnassignedEcPoint::from(g_as_ecpoint),
				signature: (
					UnassignedInteger::from(signature.0),
					UnassignedInteger::from(signature.1),
				),
				msg_hash: UnassignedInteger::from(msg_hash),
				s_inv: UnassignedInteger::from(s_inv),
			}
		}
	}

	impl Circuit<Fr> for TestEcdsaCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				public_key: UnassignedEcPoint::without_witnesses(),
				g_as_ecpoint: UnassignedEcPoint::without_witnesses(),
				signature: (
					UnassignedInteger::without_witnesses(),
					UnassignedInteger::without_witnesses(),
				),
				msg_hash: UnassignedInteger::without_witnesses(),
				s_inv: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let aux_assigner = AuxAssigner::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new();
			let auxes = aux_assigner.synthesize(
				&config.common,
				&config.aux,
				layouter.namespace(|| "aux assigner"),
			)?;

			let public_key_assigner = PointAssigner::new(self.public_key.clone());
			let public_key = public_key_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "public_key assigner"),
			)?;

			let g_as_ecpoint_assigner = PointAssigner::new(self.g_as_ecpoint.clone());
			let g_as_ecpoint = g_as_ecpoint_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "g_as_ec_point assigner"),
			)?;

			let signature_left_assigner = IntegerAssigner::new(self.signature.clone().0);
			let signature_left = signature_left_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "signature_left assigner"),
			)?;

			let signature_right_assigner = IntegerAssigner::new(self.signature.clone().1);
			let signature_right = signature_right_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "signature_right assigner"),
			)?;

			let signature = (signature_left, signature_right);

			let msg_hash_assigner = IntegerAssigner::new(self.msg_hash.clone());
			let msg_hash = msg_hash_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "msg_hash assigner"),
			)?;

			let s_inv_assigner = IntegerAssigner::new(self.s_inv.clone());
			let s_inv = s_inv_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "s_inv assigner"),
			)?;

			let chip =
				EcdsaChipset::new(public_key, g_as_ecpoint, signature, msg_hash, s_inv, auxes);

			chip.synthesize(
				&config.common,
				&config.ecdsa,
				layouter.namespace(|| "ecdsa_verify"),
			)?;
			Ok(())
		}
	}

	#[test]
	fn test_ecdsa() {
		// Test Halo2 ECDSA verify
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let public_key = keypair.public_key.clone();

		let msg_hash = Fq::from_u128(123456789);
		let msg_hash_integer = Integer::from_w(msg_hash);

		let signature = keypair.sign(msg_hash.clone(), rng);
		let s_inv_fq = big_to_fe::<Fq>(signature.1.value()).invert().unwrap();
		let s_inv = Integer::from_w(s_inv_fq);

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);

		let circuit =
			TestEcdsaCircuit::new(public_key, g_as_ecpoint, signature, msg_hash_integer, s_inv);
		let k = 15;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
