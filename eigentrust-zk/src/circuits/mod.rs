use self::{
	dynamic_sets::{native::EigenTrustSet as NativeEigenTrustSet, EigenTrustSet},
	threshold::{native::Threshold, ThresholdCircuit},
};
use crate::{
	ecdsa::native::{EcdsaKeypair, PublicKey, Signature},
	eddsa::EddsaChipset,
	edwards::params::BabyJubJub,
	params::{
		ecc::{bn254::Bn254Params, secp256k1::Secp256k1Params},
		hasher::poseidon_bn254_5x5::Params,
		rns::{bn256::Bn256_4_68, secp256k1::Secp256k1_4_68},
	},
	poseidon::{
		native::{sponge::PoseidonSponge, Poseidon},
		sponge::StatefulSpongeChipset,
		FullRoundChip, PartialRoundChip, PoseidonChipset,
	},
};
use halo2::halo2curves::{
	bn256::{Bn256, Fr as Scalar},
	secp256k1::Secp256k1Affine,
};
use num_rational::BigRational;

/// EigenTrustSet
pub mod dynamic_sets;
/// Opinion gadgets + native version
pub mod opinion;
/// Utility for checking the score threshold
pub mod threshold;

/// Number of peers in the set
pub const NUM_NEIGHBOURS: usize = 4;
/// Number of iterations to run until convergence
pub const NUM_ITERATIONS: usize = 20;
/// Intial score (pre-trust)
pub const INITIAL_SCORE: u128 = 1000;
/// Minimum peers for scores calculation
pub const MIN_PEER_COUNT: usize = 2;
/// Number of limbs for integers
pub const NUM_LIMBS: usize = 4;
/// Number of bits for integer limbs
pub const NUM_BITS: usize = 68;
/// Default width for the hasher used
pub const HASHER_WIDTH: usize = 5;
/// Number of limbs for representing big numbers in threshold checking.
pub const NUM_DECIMAL_LIMBS: usize = 2;
/// Number of digits of each limbs for threshold checking.
pub const POWER_OF_TEN: usize = 72;
/// Default polynomial degree for KZG parameters for EigenTrust circuit.
pub const ET_PARAMS_K: u32 = 20;

/// Rational score
pub type RationalScore = BigRational;
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
pub type SpongeHasher = StatefulSpongeChipset<Scalar, HASHER_WIDTH, Params>;
/// Type alias for Eddsa chip on BabyJubJub elliptic curve
pub type Eddsa = EddsaChipset<Scalar, BabyJubJub, Params>;
/// ECDSA public key.
pub type ECDSAPublicKey =
	PublicKey<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68, Secp256k1Params>;
/// ECDSA keypair.
pub type ECDSAKeypair =
	EcdsaKeypair<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68, Secp256k1Params>;
/// ECDSA signature.
pub type ECDSASignature = Signature<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68>;

/// Native EigenTrust set with 4 participants
pub type NativeEigenTrust4 = NativeEigenTrustSet<
	NUM_NEIGHBOURS,
	NUM_ITERATIONS,
	INITIAL_SCORE,
	Secp256k1Affine,
	Scalar,
	NUM_LIMBS,
	NUM_BITS,
	Secp256k1_4_68,
	Secp256k1Params,
	PoseidonNativeHasher,
	PoseidonNativeSponge,
>;
/// EigenTrust set with 4 participants
pub type EigenTrust4 = EigenTrustSet<
	NUM_NEIGHBOURS,
	NUM_ITERATIONS,
	INITIAL_SCORE,
	Secp256k1Affine,
	Scalar,
	NUM_LIMBS,
	NUM_BITS,
	Secp256k1_4_68,
	Secp256k1Params,
	PoseidonHasher,
	PoseidonNativeHasher,
	SpongeHasher,
>;

/// Native Threshold for scores computed in EigenTrust4
pub type NativeThreshold4 =
	Threshold<Scalar, NUM_DECIMAL_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>;

/// Threshold Circuit for scores computed in EigenTrust4
pub type Threshold4 = ThresholdCircuit<
	Bn256,
	NUM_DECIMAL_LIMBS,
	POWER_OF_TEN,
	NUM_NEIGHBOURS,
	INITIAL_SCORE,
	NUM_LIMBS,
	NUM_BITS,
	Bn256_4_68,
	Bn254Params,
	SpongeHasher,
	Params,
>;
