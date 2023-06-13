use super::EccParams;
use halo2::halo2curves::secp256k1::{Fp, Secp256k1Affine};
use halo2::halo2curves::CurveAffine;

struct Bn254Params;

impl EccParams<Secp256k1Affine> for Bn254Params {
	fn aux_init() -> Secp256k1Affine {
		let to_add_x = Fp::from_raw([
			0xad467b63916e17d3, 0x12498a1eac60a622, 0x9b68199adf3ffe7b, 0xdd882e3e36427390,
		]);
		let to_add_y = Fp::from_raw([
			0x12aeff734725fdec, 0x45a315ac5e816919, 0x11251eb4ee816550, 0x77783c268dbe2977,
		]);
		Secp256k1Affine::from_xy(to_add_x, to_add_y).unwrap()
	}
}

#[cfg(test)]
mod test {
	use crate::{params::rns::decompose_big, utils::fe_to_big};
	use halo2::halo2curves::secp256k1::{Fp, Fq, Secp256k1};
	use halo2::{arithmetic::Field, halo2curves::group::Curve};

	#[test]
	fn generate_secp256k1_aux() {
		use rand::rngs::OsRng;
		let random_scalar = Fq::random(OsRng);
		let g = Secp256k1::generator();
		let to_add = (g * random_scalar).to_affine();
		let x_big = fe_to_big(to_add.x);
		let y_big = fe_to_big(to_add.y);
		let x_limbs = decompose_big::<Fp, 4, 64>(x_big);
		let y_limbs = decompose_big::<Fp, 4, 64>(y_big);
		println!("{:?}", x_limbs);
		println!("{:?}", y_limbs);
	}
}
