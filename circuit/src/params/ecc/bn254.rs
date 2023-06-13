use halo2::halo2curves::{
	bn256::{Fq, G1Affine},
	CurveAffine,
};

use super::EccParams;

struct Bn254Params;

impl EccParams<G1Affine> for Bn254Params {
	fn aux_init() -> G1Affine {
		let to_add_x = Fq::from_raw([
			0xc31ec539373ca785, 0x9da68395fc2377e1, 0x125da415992c10c3, 0x95a8a5d788e033e,
		]);
		let to_add_y = Fq::from_raw([
			0x48331c1ae1c20e12, 0xd8e08c497c6f41c2, 0xbd3fa8607e7558fb, 0x10d670a5ac441899,
		]);
		G1Affine::from_xy(to_add_x, to_add_y).unwrap()
	}
}

#[cfg(test)]
mod test {
	use halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::{Fq, Fr, G1Affine},
			group::Curve,
		},
	};

	use crate::{params::rns::decompose_big, utils::fe_to_big};

	#[test]
	fn generate_bn254_aux() {
		use rand::rngs::OsRng;
		let random_scalar = Fr::random(OsRng);
		let g = G1Affine::generator();
		let to_add = (g * random_scalar).to_affine();
		let x_big = fe_to_big(to_add.x);
		let y_big = fe_to_big(to_add.y);
		let x_limbs = decompose_big::<Fq, 4, 64>(x_big);
		let y_limbs = decompose_big::<Fq, 4, 64>(y_big);
		println!("{:?}", x_limbs);
		println!("{:?}", y_limbs);
	}
}
