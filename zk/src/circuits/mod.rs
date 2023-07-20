use crate::{
	eddsa::EddsaChipset,
	edwards::params::BabyJubJub,
	params::hasher::poseidon_bn254_5x5::Params,
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::PoseidonSpongeChipset,
		FullRoundChip, PartialRoundChip, PoseidonChipset,
	},
};
use halo2::halo2curves::bn256::Fr as Scalar;

/// EigenTrustSet
pub mod dynamic_sets;
/// Opinion gadgets + native version
pub mod opinion;
/// Utility for checking the score threshold
pub mod threshold;

/// Default width for the hasher used
pub const HASHER_WIDTH: usize = 5;
/// Type alias for the native poseidon hasher with a width of 5 and bn254 params
pub type PoseidonNativeHasher = Poseidon<Scalar, HASHER_WIDTH, Params>;
/// Type alias for native poseidon sponge with a width of 5 and bn254 params
pub type PoseidonNativeSponge = PoseidonSponge<Scalar, HASHER_WIDTH, Params>;
/// Type alias for the poseidon hasher chip with a width of 5 and bn254 params
pub type PoseidonHasher = PoseidonChipset<Scalar, HASHER_WIDTH, Params>;
/// Partial rounds of permulation chip
pub type PartialRoundHasher = PartialRoundChip<Scalar, HASHER_WIDTH, Params>;
/// Full rounds of permuation chip
pub type FullRoundHasher = FullRoundChip<Scalar, HASHER_WIDTH, Params>;
/// Type alias for the poseidon spong chip with a width of 5 and bn254 params
pub type SpongeHasher = PoseidonSpongeChipset<Scalar, HASHER_WIDTH, Params>;
/// Type alias for Eddsa chip on BabyJubJub elliptic curve
pub type Eddsa = EddsaChipset<Scalar, BabyJubJub, Params>;
