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
/// Wrong Modulus in Native Modulus for Base Field: https://www.wolframalpha.com/input?i=115792089237316195423570985008687907853269984665640564039457584007908834671663+mod+21888242871839275222246405745257275088548364400416034343698204186575808495617
/// https://www.wolframalpha.com/input?i=6350874878119819312338956282401532410528162663560392320966563075029792193578+in+hex
///
/// Wrong Modulus in Native Modulus for Scalar Field: https://www.wolframalpha.com/input?i=115792089237316195423570985008687907852837564279074904382605163141518161494337+mod+21888242871839275222246405745257275088548364400416034343698204186575808495617
/// https://www.wolframalpha.com/input?i=6350874878119819312338956282401532410095742276994732664114142208639119016252+in+hex
use super::*;

#[derive(Debug, Clone, PartialEq, Default)]
/// Struct for the Secp256k1 Base Field as the wrong field. From https://github.com/privacy-scaling-explorations/halo2curves/blob/main/src/secp256k1/fp.rs
pub struct Secp256k1BaseField4_68;

impl RnsParams<secp256k1Fp, Fr, 4, 68> for Secp256k1BaseField4_68 {
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
		let limb0 = Fr::from_u128(140029228562771870679);
		let limb1 = Fr::from_u128(54120732105655028278);
		let limb2 = Fr::from_u128(18037446069688272914);
		let limb3 = Fr::from_u128(604307990016668);
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
		let limb0 = Fr::from_u128(252992975607365614304);
		let limb1 = Fr::from_u128(246373929609370463456);
		let limb2 = Fr::from_u128(147045207087024714823);
		let limb3 = Fr::from_u128(661255989794087);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(100703685036303013336);
		let limb1 = Fr::from_u128(142420853763560729700);
		let limb2 = Fr::from_u128(70276077464837018148);
		let limb3 = Fr::from_u128(3853257862753614);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_x() -> [Fr; 4] {
		let limb0 = Fr::from_u128(112383145895474475045);
		let limb1 = Fr::from_u128(77353473636075571401);
		let limb2 = Fr::from_u128(168420387443881604905);
		let limb3 = Fr::from_u128(4333384540989656);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(34847995348328062435);
		let limb1 = Fr::from_u128(138213416034526311223);
		let limb2 = Fr::from_u128(277306927096733657243);
		let limb3 = Fr::from_u128(158537774519885);
		[limb0, limb1, limb2, limb3]
	}

	fn invert(input: BigUint) -> Option<Integer<secp256k1Fp, Fr, 4, 68, Self>> {
		let a_w = big_to_fe::<secp256k1Fp>(input);
		let inv_w = a_w.invert();
		inv_w
			.map(|inv| {
				Integer::<secp256k1Fp, Fr, 4, 68, Secp256k1BaseField4_68>::new(fe_to_big(inv))
			})
			.into()
	}
}

#[derive(Debug, Clone, PartialEq, Default)]
/// Struct for the Secp256k1 Scalar Field as the wrong field.
/// From https://github.com/privacy-scaling-explorations/halo2curves/blob/main/src/secp256k1/fq.rs
pub struct Secp256k1ScalarField4_68;

impl RnsParams<secp256k1Fq, Fr, 4, 68> for Secp256k1ScalarField4_68 {
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
		let limb0 = Fr::from_u128(218440734761789537989);
		let limb1 = Fr::from_u128(55585829363597246514);
		let limb2 = Fr::from_u128(18037446069688272914);
		let limb3 = Fr::from_u128(604307990016668);
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
		let limb0 = Fr::from_u128(252992975607365614304);
		let limb1 = Fr::from_u128(246373929609370463456);
		let limb2 = Fr::from_u128(147045207087024714823);
		let limb3 = Fr::from_u128(661255989794087);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(100703685036303013336);
		let limb1 = Fr::from_u128(142420853763560729700);
		let limb2 = Fr::from_u128(70276077464837018148);
		let limb3 = Fr::from_u128(3853257862753614);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_x() -> [Fr; 4] {
		let limb0 = Fr::from_u128(112383145895474475045);
		let limb1 = Fr::from_u128(77353473636075571401);
		let limb2 = Fr::from_u128(168420387443881604905);
		let limb3 = Fr::from_u128(4333384540989656);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(34847995348328062435);
		let limb1 = Fr::from_u128(138213416034526311223);
		let limb2 = Fr::from_u128(277306927096733657243);
		let limb3 = Fr::from_u128(158537774519885);
		[limb0, limb1, limb2, limb3]
	}
}

#[test]
fn generate_secp256k1_aux() {
	use halo2::halo2curves::secp256k1::*;
	use rand::rngs::OsRng;
	let random_scalar = Fq::random(OsRng);
	let g = Secp256k1::generator();
	let to_add = (g * random_scalar).to_affine();
	println!("random_scalar: {:?}", random_scalar);
	println!("to_add: {:?}", to_add);
	println!("to_add.x: {:?}", to_add.x);
	println!("to_add.y: {:?}", to_add.y);

	let to_sub = make_mul_aux(to_add);
	println!("to_sub: {:?}", to_sub);
	println!("to_sub.x: {:?}", to_sub.x);
	println!("to_sub.y: {:?}", to_sub.y);
}
