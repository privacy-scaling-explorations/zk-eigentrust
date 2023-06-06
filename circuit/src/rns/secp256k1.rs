/// We implement two structs one for the Secpk256k1 Base Field as the wrong
/// field and one for the Secp256k1 Scalar Field as the wrong field. The native
/// field is the BN256 scalar field. The reason for implementing both these
/// structs is that ECDSA verification contains operations in both fields.
///
/// Secp25k1 aux points
/// to_add.x: 0x25968a86095277f8a984c449dc3447d5b2007a27b9eece0db6fb9ae69217bae0
/// to_add.y: 0xdb08482232d4e3cf46c81d9b71d2247b87c83eb80e46c645758b5bfd51a955d8
/// to_sub.x: 0xf6530b63da8d89214d6a0cfe38f7294317ebe6f8cd408c9617a123c2b0a7b025
/// to_sub.y: 0x0903073bbd64df08681cf59bf4689b77e18b198eb3833371e39cf322ff8f1de3
///
/// Wrong Modulus in Native Modulus for Base Field: https://www.wolframalpha.com/input?\
/// i=115792089237316195423570985008687907853269984665640564039457584007908834671663+mod+\
/// 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// https://www.wolframalpha.com/input?i=6350874878119819312338956282401532410528162663560392320966563075029792193578+in+hex
///
/// Negative Wrong Modulus for Base Field: https://www.wolframalpha.com/input?\
/// i=-115792089237316195423570985008687907853269984665640564039457584007908834671663+mod+2%5E272
///
/// Wrong Modulus in Native Modulus for Scalar Field: https://www.wolframalpha.com/input?\
/// i=115792089237316195423570985008687907852837564279074904382605163141518161494337+mod+\
/// 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// https://www.wolframalpha.com/input?i=6350874878119819312338956282401532410095742276994732664114142208639119016252+in+hex
///
/// Negative Wrong Modulus for Scalar Field: https://www.wolframalpha.com/input?\
/// i=-115792089237316195423570985008687907852837564279074904382605163141518161494337+mod+2%5E272
use super::*;
use halo2::halo2curves::secp256k1::{Fp, Fq};

#[derive(Debug, Clone, PartialEq, Default)]
/// Struct for the Secp256k1 Base and Scalar Field as the wrong field.
/// From https://github.com/privacy-scaling-explorations/halo2curves/blob/main/src/secp256k1/fp.rs
/// From https://github.com/privacy-scaling-explorations/halo2curves/blob/main/src/secp256k1/fq.rs
pub struct Secp256k1_4_68;

impl RnsParams<Fp, Fr, 4, 68> for Secp256k1_4_68 {
	fn native_modulus() -> BigUint {
		BigUint::from_str(
			"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		)
		.unwrap()
	}

	fn wrong_modulus() -> BigUint {
		BigUint::from_str(
			"115792089237316195423570985008687907853269984665640564039457584007908834671663",
		)
		.unwrap()
	}

	fn wrong_modulus_in_native_modulus() -> Fr {
		Fr::from_raw([
			0xac96341b4ffffc2a, 0x36fc76959f60cd29, 0x666ea36f7879462e, 0x0e0a77c19a07df2f,
		])
	}

	fn negative_wrong_modulus_decomposed() -> [Fr; 4] {
		let limb0 = Fr::from_u128(4294968273);
		let limb1 = Fr::from_u128(0);
		let limb2 = Fr::from_u128(0);
		let limb3 = Fr::from_u128(295143401579725455360);
		[limb0, limb1, limb2, limb3]
	}

	fn right_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([
			0xf8e4610fb396ee5, 0xb42e346981868e48, 0x1dbc9c192fc7933a, 0xb603a5609b3f6f8,
		]);
		let limb2 = Fr::from_raw([
			0x568bea8e0766f9dd, 0xa31a140f219532a9, 0x1a908db2cea9b991, 0x1b7c016fe8acfaed,
		]);
		let limb3 = Fr::from_raw([
			0x769b0bf04e2f27cc, 0x55a33201cd88df51, 0x338287b1e0bedd99, 0x523513296c10199,
		]);
		[limb0, limb1, limb2, limb3]
	}

	fn left_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([0x0, 0x10, 0x0, 0x0]);
		let limb2 = Fr::from_raw([0x0, 0x0, 0x100, 0x0]);
		let limb3 = Fr::from_raw([0x0, 0x0, 0x0, 0x1000]);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_x() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000a30efcc2747d66b3d);
		let limb1 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000871230a93e8f70fec);
		let limb2 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000032aa8e8ae3d48867b);
		let limb3 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000000651634b333363);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_y() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000081572b396b37895ae);
		let limb1 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000009c76a9f8cd73e45e9);
		let limb2 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000a961227714c36843);
		let limb3 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000000003694b4beb8d22);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_x() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000000755bbc5ebffeaae);
		let limb1 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000024f1782601a7c8fbc);
		let limb2 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000004c4c611ef52bed05d);
		let limb3 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000000055937c691a1d5);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_y() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000a50ce3417d9214a76);
		let limb1 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000007d3c5522e30a7c244);
		let limb2 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000e26a38d7bfaf7cbef);
		let limb3 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000000688f2e6be93f4);
		[limb0, limb1, limb2, limb3]
	}
}

impl RnsParams<Fq, Fr, 4, 68> for Secp256k1_4_68 {
	fn native_modulus() -> BigUint {
		BigUint::from_str(
			"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		)
		.unwrap()
	}

	fn wrong_modulus() -> BigUint {
		BigUint::from_str(
			"115792089237316195423570985008687907852837564279074904382605163141518161494337",
		)
		.unwrap()
	}

	fn wrong_modulus_in_native_modulus() -> Fr {
		Fr::from_raw([
			0x6c6892a92036413c, 0xf1ab537c4ea96d65, 0x666ea36f7879462c, 0x0e0a77c19a07df2f,
		])
	}

	fn negative_wrong_modulus_decomposed() -> [Fr; 4] {
		let limb0 = Fr::from_u128(78411506203312635583);
		let limb1 = Fr::from_u128(1465097257942218236);
		let limb2 = Fr::from_u128(0);
		let limb3 = Fr::from_u128(295143401579725455360);
		[limb0, limb1, limb2, limb3]
	}

	fn right_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([
			0xf8e4610fb396ee5, 0xb42e346981868e48, 0x1dbc9c192fc7933a, 0xb603a5609b3f6f8,
		]);
		let limb2 = Fr::from_raw([
			0x568bea8e0766f9dd, 0xa31a140f219532a9, 0x1a908db2cea9b991, 0x1b7c016fe8acfaed,
		]);
		let limb3 = Fr::from_raw([
			0x769b0bf04e2f27cc, 0x55a33201cd88df51, 0x338287b1e0bedd99, 0x523513296c10199,
		]);
		[limb0, limb1, limb2, limb3]
	}

	fn left_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([0x0, 0x10, 0x0, 0x0]);
		let limb2 = Fr::from_raw([0x0, 0x0, 0x100, 0x0]);
		let limb3 = Fr::from_raw([0x0, 0x0, 0x0, 0x1000]);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_x() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000a30efcc2747d66b3d);
		let limb1 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000871230a93e8f70fec);
		let limb2 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000032aa8e8ae3d48867b);
		let limb3 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000000651634b333363);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_y() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000081572b396b37895ae);
		let limb1 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000009c76a9f8cd73e45e9);
		let limb2 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000a961227714c36843);
		let limb3 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000000003694b4beb8d22);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_x() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000000755bbc5ebffeaae);
		let limb1 =
			Fr::from_u128(0x0000000000000000000000000000000000000000000000024f1782601a7c8fbc);
		let limb2 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000004c4c611ef52bed05d);
		let limb3 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000000055937c691a1d5);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_y() -> [Fr; 4] {
		let limb0 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000a50ce3417d9214a76);
		let limb1 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000007d3c5522e30a7c244);
		let limb2 =
			Fr::from_u128(0x00000000000000000000000000000000000000000000000e26a38d7bfaf7cbef);
		let limb3 =
			Fr::from_u128(0x000000000000000000000000000000000000000000000000000688f2e6be93f4);
		[limb0, limb1, limb2, limb3]
	}
}

#[cfg(test)]
mod test {
	use crate::{
		integer::native::Integer,
		rns::{make_mul_aux, secp256k1::Secp256k1_4_68},
	};
	use halo2::halo2curves::bn256::Fr;
	use halo2::{arithmetic::Field, halo2curves::group::Curve};

	#[test]
	fn generate_secp256k1_aux() {
		use halo2::halo2curves::secp256k1::*;
		use rand::rngs::OsRng;
		let random_scalar = Fq::random(OsRng);
		let g = Secp256k1::generator();
		let to_add = (g * random_scalar).to_affine();
		println!("random_scalar: {:?}", random_scalar);
		println!("to_add: {:?}", to_add);
		println!(
			"to_add.x: {:?}",
			Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::from_w(to_add.x)
		);
		println!(
			"to_add.y: {:?}",
			Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::from_w(to_add.y)
		);

		let to_sub = make_mul_aux(to_add);
		println!("to_sub: {:?}", to_sub);
		println!(
			"to_sub.x: {:?}",
			Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::from_w(to_sub.x)
		);
		println!(
			"to_sub.y: {:?}",
			Integer::<Fp, Fr, 4, 68, Secp256k1_4_68>::from_w(to_sub.y)
		);
	}
}
