/// Native version of Opinion
pub mod native;

use crate::{
	circuits::dynamic_sets::native::AttestationFr,
	ecc::generic::{AssignedAux, AssignedEcPoint},
	ecdsa::{AssignedPublicKey, AssignedSignature, EcdsaChipset, EcdsaConfig, UnassignedSignature},
	gadgets::{
		main::{IsEqualChipset, IsZeroChipset, MainConfig, MulAddChipset, SelectChipset},
		set::{SetChipset, SetConfig},
	},
	integer::AssignedInteger,
	params::{ecc::EccParams, rns::RnsParams},
	Chipset, CommonConfig, FieldExt, HasherChipset, RegionCtx, SpongeHasherChipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::{bn256::Fr, CurveAffine},
	plonk::Error,
};
use std::marker::PhantomData;

/// Default with of the hasher used in OpinionChipset
pub const WIDTH: usize = 5;

/// Assigned Attestation structure.
#[derive(Debug, Clone)]
pub struct AssignedAttestation<N: FieldExt> {
	/// Ethereum address of peer being rated
	pub about: AssignedCell<N, N>,
	/// Unique identifier for the action being rated
	pub domain: AssignedCell<N, N>,
	/// Given rating for the action
	pub value: AssignedCell<N, N>,
	/// Optional field for attaching additional information to the attestation
	pub message: AssignedCell<N, N>,
}

impl<N: FieldExt> AssignedAttestation<N> {
	/// Creates a new AssignedAttestation
	pub fn new(
		about: AssignedCell<N, N>, domain: AssignedCell<N, N>, value: AssignedCell<N, N>,
		message: AssignedCell<N, N>,
	) -> Self {
		Self { about, domain, value, message }
	}
}

/// Unassigned Attestation structure.
#[derive(Debug, Clone)]
pub struct UnassignedAttestation<N: FieldExt> {
	/// Ethereum address of peer being rated
	pub about: Value<N>,
	/// Unique identifier for the action being rated
	pub domain: Value<N>,
	/// Given rating for the action
	pub value: Value<N>,
	/// Optional field for attaching additional information to the attestation
	pub message: Value<N>,
}

impl<N: FieldExt> UnassignedAttestation<N> {
	/// Creates a new AssignedAttestation
	pub fn new(about: Value<N>, domain: Value<N>, value: Value<N>, message: Value<N>) -> Self {
		Self { about, domain, value, message }
	}
}

impl From<AttestationFr> for UnassignedAttestation<Fr> {
	fn from(att: AttestationFr) -> Self {
		Self {
			about: Value::known(att.about),
			domain: Value::known(att.domain),
			value: Value::known(att.value),
			message: Value::known(att.message),
		}
	}
}

/// AssignedSignedAttestation structure.
#[derive(Debug, Clone)]
pub struct AssignedSignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Attestation
	attestation: AssignedAttestation<N>,
	// Signature
	signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedSignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new AssignedSignedAttestation
	pub fn new(
		attestation: AssignedAttestation<N>,
		signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { attestation, signature }
	}
}

/// AssignedSignedAttestation structure.
#[derive(Debug, Clone)]
pub struct UnassignedSignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Attestation
	attestation: UnassignedAttestation<N>,
	// Signature
	signature: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	UnassignedSignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new AssignedSignedAttestation
	pub fn new(
		attestation: UnassignedAttestation<N>,
		signature: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { attestation, signature }
	}
}

// TODO: Use this when dynamic_set ecdsa stops using hardcoded values
// impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
// 	From<SignedAttestation> for UnassignedSignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
// where
// 	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
// 	C::Base: FieldExt,
// 	C::ScalarExt: FieldExt,
// {
// 	fn from(signed_att: SignedAttestation) -> Self {
// 		Self {
// 			attestation: UnassignedAttestation::from(signed_att.attestation),
// 			signature: UnassignedSignature::from(signed_att.signature),
// 		}
// 	}
// }

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct OpinionConfig<F: FieldExt, H, S>
where
	H: HasherChipset<F, WIDTH>,
	S: SpongeHasherChipset<F>,
{
	ecdsa: EcdsaConfig,
	main: MainConfig,
	set: SetConfig,
	hasher: H::Config,
	sponge: S::Config,
}

impl<F: FieldExt, H, S> OpinionConfig<F, H, S>
where
	H: HasherChipset<F, WIDTH>,
	S: SpongeHasherChipset<F>,
{
	/// Construct a new config
	pub fn new(
		ecdsa: EcdsaConfig, main: MainConfig, set: SetConfig, hasher: H::Config, sponge: S::Config,
	) -> Self {
		Self { ecdsa, main, set, hasher, sponge }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct OpinionChipset<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	const NUM_NEIGHBOURS: usize,
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
	S: SpongeHasherChipset<N>,
{
	/// Attestations towards other peers
	attestations: Vec<AssignedSignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
	/// Public key of the attester
	public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	/// Set of peers
	set: Vec<AssignedCell<N, N>>,
	/// Message hash as AssignedInteger
	msg_hash: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
	/// Generator as EC point
	g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	/// Signature s Inverse
	s_inv: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
	/// Aux for to_add and to_sub
	aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	/// Left shifters for composing integers
	left_shifters: [AssignedCell<N, N>; NUM_LIMBS],
	/// Constructs a phantom data for the hasher.
	_hasher: PhantomData<(H, S, EC)>,
}

impl<
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		const NUM_NEIGHBOURS: usize,
		H,
		S,
		P,
		EC,
	> OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, NUM_NEIGHBOURS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N>,
{
	/// Create a new chip.
	pub fn new(
		attestations: Vec<AssignedSignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
		public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>, set: Vec<AssignedCell<N, N>>,
		msg_hash: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
		g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
		aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		left_shifters: [AssignedCell<N, N>; NUM_LIMBS],
	) -> Self {
		Self {
			attestations,
			public_key,
			set,
			msg_hash,
			g_as_ecpoint,
			s_inv,
			aux,
			left_shifters,
			_hasher: PhantomData,
		}
	}
}

impl<
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		const NUM_NEIGHBOURS: usize,
		H,
		S,
		P,
		EC,
	> Chipset<N> for OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, NUM_NEIGHBOURS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N>,
{
	type Config = OpinionConfig<N, H, S>;
	type Output = (Vec<AssignedCell<N, N>>, AssignedCell<N, N>);

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		// TODO: Checks given set for the public key

		let (zero, one) = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_fixed(common.fixed[0], N::ZERO)?;
				let one = ctx.assign_fixed(common.fixed[1], N::ONE)?;

				Ok((zero, one))
			},
		)?;

		let mut scores = vec![zero.clone(); self.set.len()];
		let mut hashes = Vec::new();

		// Hashing default values for default attestation
		let hash = H::new([(); WIDTH].map(|_| zero.clone()));
		let default_hash = hash.finalize(
			common,
			&config.hasher,
			layouter.namespace(|| "default_hash"),
		)?;

		for i in 0..NUM_NEIGHBOURS {
			// Checking pubkey and attestation values if they are default or not (default is zero)
			let is_zero_chip = IsZeroChipset::new(self.set[i].clone());
			let is_default_pubkey = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "is_default_pubkey"),
			)?;

			let att = self.attestations[i].clone();
			let is_zero_chip = IsZeroChipset::new(att.attestation.about.clone());
			let att_about = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_about"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.domain.clone());
			let att_domain = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_domain"),
			)?;

			let multi_and_check = vec![is_default_pubkey, att_about, att_domain];

			// Checks if there is a zero value. If there is a zero value in the set that means one of the variable is not default.
			// Basically, instead of doing 3 AND operation we did one set check
			let set_chip = SetChipset::new(multi_and_check, zero.clone());
			let is_default_values_zero = set_chip.synthesize(
				common,
				&config.set,
				layouter.namespace(|| "set_check_zero"),
			)?;

			// Checks equality of the attestation about and set index
			let is_equal_chip =
				IsEqualChipset::new(att.attestation.about.clone(), self.set[i].clone());
			let equality_check_set_about = is_equal_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "is_equal_chipset_set"),
			)?;

			let hash = H::new([
				att.attestation.about,
				att.attestation.domain,
				att.attestation.value.clone(),
				att.attestation.message.clone(),
				zero.clone(),
			]);
			let att_hash =
				hash.finalize(common, &config.hasher, layouter.namespace(|| "att_hash"))?;

			let mut compose_msg = zero.clone();
			for j in 0..NUM_LIMBS {
				let muladd_chipset = MulAddChipset::new(
					self.msg_hash[i].limbs[j].clone(),
					self.left_shifters[j].clone(),
					compose_msg,
				);
				compose_msg = muladd_chipset.synthesize(
					common,
					&config.main,
					layouter.namespace(|| "mul_add"),
				)?;
			}

			// Constraint equality for the msg_hash from hasher and constructor
			// Constraint equality for the set and att.about
			layouter.assign_region(
				|| "constraint equality",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.constrain_equal(att_hash[0].clone(), compose_msg.clone())?;
					ctx.constrain_equal(equality_check_set_about.clone(), one.clone())?;
					Ok(())
				},
			)?;

			let chip = EcdsaChipset::new(
				self.public_key.clone(),
				self.g_as_ecpoint.clone(),
				self.attestations[i].signature.clone(),
				self.msg_hash[i].clone(),
				self.s_inv[i].clone(),
				self.aux.clone(),
			);
			chip.synthesize(common, &config.ecdsa, layouter.namespace(|| "ecdsa_verify"))?;

			scores[i] = att.attestation.value;

			// Select chip for if case
			let select_chip = SelectChipset::new(
				is_default_values_zero,
				att_hash[0].clone(),
				default_hash[0].clone(),
			);
			let selected_value = select_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "select chipset"),
			)?;

			hashes.push(selected_value);
		}

		let mut sponge = S::init(common, layouter.namespace(|| "sponge"))?;
		sponge.update(&hashes);
		let op_hash = sponge.squeeze(common, &config.sponge, layouter.namespace(|| "squeeze!"))?;

		Ok((scores, op_hash))
	}
}

#[cfg(test)]
mod test {

	use super::native::Opinion;
	use super::{
		AssignedAttestation, AssignedSignedAttestation, OpinionChipset, OpinionConfig, WIDTH,
	};

	use crate::circuits::dynamic_sets::native::{
		field_value_from_pub_key, AttestationFr, SignedAttestation,
	};
	use crate::circuits::PoseidonNativeHasher;
	use crate::ecc::generic::{AuxAssigner, PointAssigner, UnassignedEcPoint};
	use crate::ecc::{
		AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
		EccUnreducedLadderConfig,
	};
	use crate::ecdsa::native::{EcdsaKeypair, PublicKey};
	use crate::ecdsa::{EcdsaConfig, SignatureAssigner, UnassignedSignature};
	use crate::ecdsa::{PublicKeyAssigner, UnassignedPublicKey};
	use crate::gadgets::absorb::AbsorbChip;
	use crate::gadgets::set::{SetChip, SetConfig};
	use crate::integer::{
		IntegerAddChip, IntegerAssigner, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
		IntegerSubChip, LeftShiftersAssigner, UnassignedInteger,
	};
	use crate::params::ecc::secp256k1::Secp256k1Params;

	use crate::params::hasher::poseidon_bn254_5x5::Params;
	use crate::params::rns::secp256k1::Secp256k1_4_68;
	use crate::poseidon::sponge::{PoseidonSpongeConfig, StatefulSpongeChipset};
	use crate::poseidon::{FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig};
	use crate::utils::big_to_fe;
	use crate::UnassignedValue;
	use crate::{
		ecc::generic::native::EcPoint,
		gadgets::{
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::native::Integer,
		Chip, CommonConfig,
	};
	use crate::{Chipset, RegionCtx};
	use halo2::arithmetic::Field;
	use halo2::circuit::{Region, Value};
	use halo2::dev::MockProver;
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
	use itertools::Itertools;

	type W = Fp;
	type SecpScalar = Fq;
	type N = Fr;
	type C = Secp256k1Affine;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;
	type H = PoseidonChipset<N, WIDTH, Params>;
	type S = StatefulSpongeChipset<N, WIDTH, Params>;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		opinion: OpinionConfig<N, H, S>,
		aux: AuxConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<N>) -> Self {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));
			let bits2num_selector = Bits2NumChip::configure(&common, meta);
			let set_selector = SetChip::configure(&common, meta);
			let set = SetConfig::new(main.clone(), set_selector);

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
			let absorb_selector = AbsorbChip::<_, WIDTH>::configure(&common, meta);
			let sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

			let opinion = OpinionConfig::new(ecdsa, main, set, poseidon, sponge);
			TestConfig { common, opinion, aux }
		}
	}

	struct TestOpinionCircuit {
		attestations: Vec<SignedAttestation>,
		set: Vec<N>,
		public_key: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		msg_hash: Vec<UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>>,
		s_inv: Vec<UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>>,
	}

	impl TestOpinionCircuit {
		fn new(
			attestations: Vec<SignedAttestation>, set: Vec<N>,
			public_key: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			g_as_ecpoint: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			msg_hash: Vec<Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>>,
			s_inv: Vec<Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>>,
		) -> Self {
			Self {
				attestations,
				set,
				public_key: UnassignedPublicKey::new(public_key),
				g_as_ecpoint: UnassignedEcPoint::from(g_as_ecpoint),

				msg_hash: msg_hash.iter().map(|x| UnassignedInteger::from(x.clone())).collect_vec(),
				s_inv: s_inv.iter().map(|x| UnassignedInteger::from(x.clone())).collect_vec(),
			}
		}
	}

	impl Circuit<Fr> for TestOpinionCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				attestations: self.attestations.clone(),
				set: self.set.iter().map(|_| N::default()).collect_vec(),
				public_key: UnassignedPublicKey::without_witnesses(),
				g_as_ecpoint: UnassignedEcPoint::without_witnesses(),
				msg_hash: self
					.msg_hash
					.iter()
					.map(|_| UnassignedInteger::without_witnesses())
					.collect_vec(),
				s_inv: self
					.s_inv
					.iter()
					.map(|_| UnassignedInteger::without_witnesses())
					.collect_vec(),
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

			let public_key_assigner = PublicKeyAssigner::new(self.public_key.clone());
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

			let mut msg_hash = Vec::new();
			let mut s_inv = Vec::new();

			for i in 0..self.msg_hash.len() {
				let msg_hash_assigner = IntegerAssigner::new(self.msg_hash[i].clone());
				msg_hash.push(msg_hash_assigner.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "msg_hash assigner"),
				)?);

				let s_inv_assigner = IntegerAssigner::new(self.s_inv[i].clone());
				s_inv.push(s_inv_assigner.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "s_inv assigner"),
				)?);
			}

			let set = layouter.assign_region(
				|| "assign_set",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut set = Vec::new();
					for i in 0..self.set.len() {
						set.push(
							ctx.assign_advice(config.common.advice[0], Value::known(self.set[i]))?,
						);
						ctx.next();
					}
					Ok(set)
				},
			)?;

			let mut attestations = Vec::new();

			for i in 0..self.attestations.len() {
				let signature_assigner = SignatureAssigner::new(UnassignedSignature::from(
					self.attestations[i].signature.clone(),
				));
				let signature = signature_assigner.synthesize(
					&config.common,
					&(),
					layouter.namespace(|| "signature assigner"),
				)?;

				let (about, domain, value, message) = layouter.assign_region(
					|| "assign_attestation",
					|region: Region<'_, N>| {
						let mut ctx = RegionCtx::new(region, 0);
						let att = self.attestations[i].attestation.clone();
						let about =
							ctx.assign_advice(config.common.advice[0], Value::known(att.about))?;
						let domain =
							ctx.assign_advice(config.common.advice[1], Value::known(att.domain))?;
						let value =
							ctx.assign_advice(config.common.advice[2], Value::known(att.value))?;
						let message =
							ctx.assign_advice(config.common.advice[3], Value::known(att.message))?;
						Ok((about, domain, value, message))
					},
				)?;
				let attestation = AssignedAttestation::new(about, domain, value, message);

				attestations.push(AssignedSignedAttestation::new(attestation, signature))
			}

			let left_shifters_assigner =
				LeftShiftersAssigner::<Fq, N, NUM_LIMBS, NUM_BITS, P>::default();
			let left_shifters = left_shifters_assigner.synthesize(
				&config.common,
				&(),
				layouter.namespace(|| "left_shifters"),
			)?;

			let opinion: OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, WIDTH, H, S, P, EC> =
				OpinionChipset::new(
					attestations, public_key, set, msg_hash, g_as_ecpoint, s_inv, auxes,
					left_shifters,
				);

			let (scores, op_hash) = opinion.synthesize(
				&config.common,
				&config.opinion,
				layouter.namespace(|| "opinion"),
			)?;

			for i in 0..scores.len() {
				layouter.constrain_instance(scores[i].cell(), config.common.instance, i)?;
			}
			layouter.constrain_instance(op_hash.cell(), config.common.instance, scores.len())?;

			Ok(())
		}
	}

	#[test]
	fn test_opinion() {
		// Test Opinion Chipset
		let rng = &mut rand::thread_rng();
		let keypair = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let public_key = keypair.public_key.clone();
		let public_key_fr = field_value_from_pub_key(&public_key);
		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);

		let mut set = Vec::new();
		let mut msg_hash = Vec::new();
		let mut s_inv = Vec::new();
		let mut attestations = Vec::new();

		for _ in 0..10 {
			let attestation = AttestationFr::new(
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
			);
			set.push(attestation.about.clone());

			let att_hasher = PoseidonNativeHasher::new([
				attestation.about,
				attestation.domain,
				attestation.value,
				attestation.message,
				Fr::zero(),
			]);
			let att_hash_bytes = att_hasher.permute()[0].to_bytes();
			let att_fq = Fq::from_bytes(&att_hash_bytes).unwrap();
			let signature = keypair.sign(att_fq.clone(), rng);
			let s_inv_fq = big_to_fe::<Fq>(signature.s.value()).invert().unwrap();

			msg_hash.push(Integer::from_w(att_fq));
			s_inv.push(Integer::from_w(s_inv_fq));
			attestations.push(SignedAttestation::new(attestation, signature));
		}
		set.push(public_key_fr);
		let opinion_native: Opinion<WIDTH> = Opinion::new(public_key.clone(), attestations.clone());
		let (_, scores, op_hash) = opinion_native.validate(set.clone());

		let mut p_ins = Vec::new();
		p_ins.extend(scores);
		p_ins.push(op_hash);
		let circuit =
			TestOpinionCircuit::new(attestations, set, public_key, g_as_ecpoint, msg_hash, s_inv);
		let k = 18;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
