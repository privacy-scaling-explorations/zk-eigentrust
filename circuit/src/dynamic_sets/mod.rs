/// Native version of EigenTrustSet
pub mod native;

use std::collections::HashMap;

use crate::{
	circuit::{FullRoundHasher, PartialRoundHasher},
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
		main::{AddChipset, MainChip, MainConfig, MulChipset},
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
	halo2curves::{bn256::Fr, FieldExt},
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
> {
	set: [(PublicKey, Fr); NUM_NEIGHBOURS],
	ops: HashMap<PublicKey, Opinion>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITER: usize, const INITIAL_SCORE: u128>
	EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE>
{
	/// Constructs a new EigenTrustSet circuit
	pub fn new(set: [(PublicKey, Fr); NUM_NEIGHBOURS], ops: HashMap<PublicKey, Opinion>) -> Self {
		Self { set, ops }
	}
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITER: usize, const INITIAL_SCORE: u128> Circuit<Fr>
	for EigenTrustSet<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE>
{
	type Config = EigenTrustSetConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			set: (0..NUM_NEIGHBOURS).map(|_| (PublicKey::default(), Fr::zero())).collect(),
			ops: HashMap::new(),
		}
	}

	fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let full_round_selector = FullRoundHasher::configure(&common, meta);
		let partial_round_selector = PartialRoundHasher::configure(&common, meta);
		let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

		let absorb_selector = AbsorbChip::<Fr, HASHER_WIDTH>::configure(&common, meta);
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

	fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
		todo!()
	}
}
