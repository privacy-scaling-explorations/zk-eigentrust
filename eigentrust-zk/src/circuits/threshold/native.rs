use crate::{
	params::rns::{compose_big_decimal_f, decompose_big_decimal},
	utils::fe_to_big,
	FieldExt,
};
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::{One, Zero};

/// Structure for threshold checks
pub struct Threshold<
	F: FieldExt,
	const NUM_LIMBS: usize,
	const POWER_OF_TEN: usize,
	const NUM_NEIGHBOURS: usize,
	const INITIAL_SCORE: u128,
> {
	score: F,
	num_decomposed: [F; NUM_LIMBS],
	den_decomposed: [F; NUM_LIMBS],
	threshold: F,
}

impl<
		F: FieldExt,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
		const NUM_NEIGHBOURS: usize,
		const INITIAL_SCORE: u128,
	> Threshold<F, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>
{
	/// Create new instance
	pub fn new(score: F, ratio: BigRational, threshold: F) -> Self {
		let max_score_bn = BigUint::from(NUM_NEIGHBOURS * INITIAL_SCORE as usize);
		let max_limb_value_bn = BigUint::from(10u32).pow(POWER_OF_TEN as u32) - BigUint::one();
		let max_f_bn = fe_to_big(F::ZERO - F::ONE);
		assert!(max_score_bn * max_limb_value_bn < max_f_bn);

		let num = ratio.numer();
		let den = ratio.denom();
		let max_len = NUM_LIMBS * POWER_OF_TEN;
		let bigger = num.max(den);
		let dig_len = bigger.to_string().len();
		let diff = max_len - dig_len;

		let scale = BigInt::from(10_u32).pow(diff as u32);
		let num_scaled = num * scale.clone();
		let den_scaled = den * scale;
		let num_scaled_uint = num_scaled.to_biguint().unwrap();
		let den_scaled_uint = den_scaled.to_biguint().unwrap();

		let num_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(num_scaled_uint);
		let den_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(den_scaled_uint);

		Self { score, num_decomposed, den_decomposed, threshold }
	}

	/// Method for checking the threshold for a given score
	// Constraint checks - circuits should implement from this point
	pub fn check_threshold(&self) -> bool {
		let max_score_bn = BigUint::from(NUM_NEIGHBOURS as u128 * INITIAL_SCORE);
		let threshold_bn = fe_to_big(self.threshold);
		assert!(threshold_bn < max_score_bn);

		let max_limb_value_bn = BigUint::from(10u32).pow(POWER_OF_TEN as u32);
		for limb in self.num_decomposed {
			let limb_bn = fe_to_big(limb);
			assert!(limb_bn < max_limb_value_bn);
		}
		for limb in self.den_decomposed {
			let limb_bn = fe_to_big(limb);
			assert!(limb_bn < max_limb_value_bn);
		}

		let composed_num_f =
			compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(self.num_decomposed);
		let composed_den_f =
			compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(self.den_decomposed);
		let composed_den_f_inv = composed_den_f.invert().unwrap();
		let res_f = composed_num_f * composed_den_f_inv;
		assert!(res_f == self.score);

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let last_limb_num = *self.num_decomposed.last().unwrap();
		let last_limb_den = *self.den_decomposed.last().unwrap();
		let last_limb_num_bn = fe_to_big(last_limb_num);
		let last_limb_den_bn = fe_to_big(last_limb_den);

		assert!(!last_limb_den_bn.is_zero());

		let comp = last_limb_den * self.threshold;
		let comp_bn = fe_to_big(comp);

		last_limb_num_bn >= comp_bn
	}
}

#[cfg(test)]
mod tests {
	use crate::{
		circuits::{
			dynamic_sets::native::{Attestation, EigenTrustSet, SignedAttestation},
			PoseidonNativeHasher, PoseidonNativeSponge, HASHER_WIDTH,
		},
		ecdsa::native::EcdsaKeypair,
		params::{
			ecc::secp256k1::Secp256k1Params,
			rns::{compose_big_decimal, secp256k1::Secp256k1_4_68},
		},
		utils::big_to_fe,
	};
	use halo2::{
		arithmetic::Field,
		halo2curves::{bn256::Fr, ff::PrimeField, secp256k1::Secp256k1Affine},
	};
	use itertools::Itertools;
	use num_bigint::{BigInt, ToBigInt};
	use num_rational::BigRational;
	use num_traits::FromPrimitive;
	use rand::{thread_rng, Rng};

	use super::*;

	const DOMAIN: u128 = 42;
	type C = Secp256k1Affine;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;
	type H = PoseidonNativeHasher;
	type SH = PoseidonNativeSponge;

	#[test]
	fn test_check_threshold_1() {
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 3;
		const NUM_NEIGHBOURS: usize = 4;
		const INITIAL_SCORE: u128 = 1000;

		let threshold = 346;
		let num = 345111;
		let den = 1000;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = N::from_u128(threshold);
		let num_fr = N::from_u128(num);
		let den_fr = N::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold();

		assert!(!is_bigger);
	}

	#[test]
	fn test_check_threshold_2() {
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 3;
		const NUM_NEIGHBOURS: usize = 4;
		const INITIAL_SCORE: u128 = 1000;

		let threshold = 344;
		let num = 345111;
		let den = 1000;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = N::from_u128(threshold);
		let num_fr = N::from_u128(num);
		let den_fr = N::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold();

		assert!(is_bigger);
	}

	#[test]
	fn test_check_threshold_3() {
		const NUM_LIMBS: usize = 5;
		const POWER_OF_TEN: usize = 3;
		const NUM_NEIGHBOURS: usize = 4;
		const INITIAL_SCORE: u128 = 1000;

		let threshold = 346;
		let num = 347123456789123;
		let den = 1984263563965;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = N::from_u128(threshold);
		let num_fr = N::from_u128(num);
		let den_fr = N::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
			Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold();

		assert!(is_bigger);
	}

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		keypair: &EcdsaKeypair<C, N, NUM_LIMBS, NUM_BITS, P, EC>, addrs: &[N], scores: &[N],
	) -> Vec<Option<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>> {
		assert!(addrs.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);
		let rng = &mut thread_rng();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if addrs[i] == N::zero() {
				res.push(None)
			} else {
				let (about, key, value, message) = (addrs[i], N::zero(), scores[i], N::zero());
				let attestation = Attestation::new(about, key, value, message);
				let msg = big_to_fe(fe_to_big(
					attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>(),
				));
				let signature = keypair.sign(msg, rng);
				let signed_attestation = SignedAttestation::new(attestation, signature);

				res.push(Some(signed_attestation));
			}
		}
		res
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		ops: Vec<Vec<N>>,
	) -> (Vec<N>, Vec<BigRational>) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypairs: Vec<EcdsaKeypair<C, N, NUM_LIMBS, NUM_BITS, P, EC>> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| EcdsaKeypair::generate_keypair(rng)).collect();

		let pks = keypairs.iter().map(|kp| kp.public_key.clone()).collect_vec();
		let addresses = pks.iter().map(|pk| pk.to_address()).collect_vec();
		// Add the publicKey to the set
		addresses.iter().for_each(|&addr| set.add_member(addr));
		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();

			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&keypairs[i], &addresses, &scores,
			);

			set.update_op(pks[i].clone(), op_i);
		}

		let s = set.converge();
		let s_ratios = set.converge_rational();

		(s, s_ratios)
	}

	#[ignore = "Scaling test takes too long to run"]
	#[test]
	fn test_scaling_4_peers() {
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		let rng = &mut thread_rng();
		let mut biggest = 0;
		for _ in 0..1000 {
			let mut ops_raw = [(); NUM_NEIGHBOURS].map(|_| [(); NUM_NEIGHBOURS].map(|_| 0));
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					ops_raw[i][j] = rng.gen::<u8>();
				}
			}

			let ops = ops_raw.map(|arr| arr.map(|x| N::from_u128(x as u128)).to_vec()).to_vec();

			let (_, s_ratios) =
				eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
					ops,
				);

			for ratio in s_ratios {
				let num_len = ratio.numer().to_string().len();
				let den_len = ratio.denom().to_string().len();
				println!("num_len: {:?}, den_len: {:?}", num_len, den_len);
				let curr = num_len.max(den_len);
				if curr > biggest {
					biggest = curr;
				}
			}
		}

		println!("{:?}", biggest);
	}

	#[ignore = "Scaling test takes too long to run"]
	#[test]
	fn test_4_peer_consts() {
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		// Printing out the optimal value for POWER_OF_TEN
		let max_score_bn = BigUint::from(NUM_NEIGHBOURS * INITIAL_SCORE as usize);
		let max_f_bn = fe_to_big(N::zero() - N::one());
		let optimal_power_of_10 = max_f_bn.to_string().len() - max_score_bn.to_string().len() - 1;
		println!("{:?}", optimal_power_of_10);

		const THRESHOLD: u128 = 1000;
		// Since the biggest value from test_scaling_4_peers was 110 we need 2 limbs to cover all of them
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 72;

		let rng = &mut thread_rng();
		for _ in 0..1000 {
			let mut ops_raw = [(); NUM_NEIGHBOURS].map(|_| [(); NUM_NEIGHBOURS].map(|_| 0));
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					ops_raw[i][j] = rng.gen::<u8>();
				}
			}

			let ops = ops_raw.map(|arr| arr.map(|x| N::from_u128(x as u128)).to_vec()).to_vec();

			let (s, s_ratios) =
				eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
					ops,
				);

			let threshold = N::from_u128(THRESHOLD);
			for (&score, ratio) in s.iter().zip(s_ratios.clone()) {
				let t: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
					Threshold::new(score, ratio, threshold);
				let is_bigger_org = t.check_threshold();

				let num = compose_big_decimal::<N, NUM_LIMBS, POWER_OF_TEN>(t.num_decomposed);
				let den = compose_big_decimal::<N, NUM_LIMBS, POWER_OF_TEN>(t.den_decomposed);
				let ratio = BigRational::new(num.to_bigint().unwrap(), den.to_bigint().unwrap());
				let ratio_prime = ratio.to_integer().to_str_radix(10).parse::<u128>().unwrap();
				let is_bigger = ratio_prime >= THRESHOLD;

				assert!(is_bigger == is_bigger_org);
				println!(
					"real score: {:?}, is bigger than {}: {:?} {:?}",
					ratio.to_integer().to_str_radix(10),
					THRESHOLD,
					is_bigger_org,
					is_bigger
				);
			}
		}
	}

	#[ignore = "Scaling test takes too long to run"]
	#[test]
	fn test_scaling_128_peers() {
		const NUM_NEIGHBOURS: usize = 128;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		let rng = &mut thread_rng();
		let mut biggest = 0;
		for _ in 0..1000 {
			let mut ops_raw = [(); NUM_NEIGHBOURS].map(|_| [(); NUM_NEIGHBOURS].map(|_| 0));
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					ops_raw[i][j] = rng.gen::<u8>();
				}
			}

			let ops = ops_raw.map(|arr| arr.map(|x| N::from_u128(x as u128)).to_vec()).to_vec();

			let (_, s_ratios) =
				eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
					ops,
				);

			for ratio in s_ratios {
				let num_len = ratio.numer().to_string().len();
				let den_len = ratio.denom().to_string().len();
				println!("num_len: {:?}, den_len: {:?}", num_len, den_len);
				let curr = num_len.max(den_len);
				if curr > biggest {
					biggest = curr;
				}
			}
		}

		println!("{:?}", biggest);
	}

	#[ignore = "Scaling test takes too long to run"]
	#[test]
	fn test_128_peer_consts() {
		const NUM_NEIGHBOURS: usize = 128;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		// Printing out the optimal value for POWER_OF_TEN
		let max_score_bn = BigUint::from(NUM_NEIGHBOURS * INITIAL_SCORE as usize);
		let max_f_bn = fe_to_big(N::zero() - N::one());
		let optimal_power_of_10 = max_f_bn.to_string().len() - max_score_bn.to_string().len() - 1;
		println!("{:?}", optimal_power_of_10);

		const THRESHOLD: u128 = 1000;
		// Since the biggest value from test_scaling_128_peers was 4222 we need 61 limbs to cover all of them
		const NUM_LIMBS: usize = 61;
		const POWER_OF_TEN: usize = 70;

		let rng = &mut thread_rng();
		for _ in 0..1000 {
			let mut ops_raw = [(); NUM_NEIGHBOURS].map(|_| [(); NUM_NEIGHBOURS].map(|_| 0));
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					ops_raw[i][j] = rng.gen::<u8>();
				}
			}

			let ops = ops_raw.map(|arr| arr.map(|x| N::from_u128(x as u128)).to_vec()).to_vec();

			let (s, s_ratios) =
				eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
					ops,
				);

			let threshold = N::from_u128(THRESHOLD);
			for (&score, ratio) in s.iter().zip(s_ratios.clone()) {
				let t: Threshold<N, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE> =
					Threshold::new(score, ratio, threshold);
				let is_bigger_org = t.check_threshold();

				let num = compose_big_decimal::<N, NUM_LIMBS, POWER_OF_TEN>(t.num_decomposed);
				let den = compose_big_decimal::<N, NUM_LIMBS, POWER_OF_TEN>(t.den_decomposed);
				let ratio = BigRational::new(num.to_bigint().unwrap(), den.to_bigint().unwrap());
				let ratio_prime = ratio.to_integer().to_str_radix(10).parse::<u128>().unwrap();
				let is_bigger = ratio_prime >= THRESHOLD;

				assert!(is_bigger == is_bigger_org);
				println!(
					"real score: {:?}, is bigger than {}: {:?} {:?}",
					ratio.to_integer().to_str_radix(10),
					THRESHOLD,
					is_bigger_org,
					is_bigger
				);
			}
		}
	}
}
