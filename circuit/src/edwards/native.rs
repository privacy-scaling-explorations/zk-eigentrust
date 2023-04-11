use crate::utils::to_bits;

use super::params::EdwardsParams;
use halo2::halo2curves::FieldExt;
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug)]
/// Constructs PointProjective objects.
pub struct PointProjective<F: FieldExt, P: EdwardsParams<F>> {
	/// Constructs a field element for the x.
	pub x: F,
	/// Constructs a field element for the y.
	pub y: F,
	/// Constructs a field element for the z.
	pub z: F,
	_p: PhantomData<P>,
}

impl<F: FieldExt, P: EdwardsParams<F>> PointProjective<F, P> {
	/// Returns affine representation from the given projective space
	/// representation.
	pub fn affine(&self) -> Point<F, P> {
		if bool::from(self.z.is_zero()) {
			return Point { x: F::zero(), y: F::zero(), _p: PhantomData };
		}

		let zinv = self.z.invert().unwrap();
		let x = self.x.mul(&zinv);
		let y = self.y.mul(&zinv);

		Point { x, y, _p: PhantomData }
	}

	/// DOUBLE operation of point `self`
	pub fn double(&self) -> Self {
		// dbl-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
		let (x3, y3, z3) = P::double(self.x, self.y, self.z);

		PointProjective { x: x3, y: y3, z: z3, _p: PhantomData }
	}

	/// ADD operation between points `self` and `q`
	pub fn add(&self, q: &Self) -> Self {
		// add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
		let (x3, y3, z3) = P::add(self.x, self.y, self.z, q.x, q.y, q.z);

		PointProjective { x: x3, y: y3, z: z3, _p: PhantomData }
	}
}

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq, Default)]
/// Configures Point objects.
pub struct Point<F: FieldExt, P: EdwardsParams<F>> {
	/// Constructs a field element for the x.
	pub x: F,
	/// Constructs a field element for the y.
	pub y: F,
	_p: PhantomData<P>,
}

impl<F: FieldExt, P: EdwardsParams<F>> Point<F, P> {
	/// Returns a new Edwards point in affine repr
	pub fn new(x: F, y: F) -> Self {
		Self { x, y, _p: PhantomData }
	}

	/// Returns projective space representation from the given affine
	/// representation.
	pub fn projective(&self) -> PointProjective<F, P> {
		PointProjective { x: self.x, y: self.y, z: F::one(), _p: PhantomData }
	}

	/// Returns scalar multiplication of the element.
	pub fn mul_scalar(&self, scalar: F) -> PointProjective<F, P> {
		let mut r: PointProjective<F, P> =
			PointProjective { x: F::zero(), y: F::one(), z: F::one(), _p: PhantomData };
		let mut exp: PointProjective<F, P> = self.projective();
		let scalar_bits = to_bits(scalar.to_repr().as_ref());
		// Double and add operation.
		for i in 0..scalar_bits.len() {
			if scalar_bits[i] {
				r = r.add(&exp);
			}
			exp = exp.double();
		}
		r
	}

	/// Returns true if the given point is equal to the element. Else, false.
	pub fn equals(&self, p: Self) -> bool {
		self.x == p.x && self.y == p.y
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::edwards::params::BabyJubJub;
	use halo2::halo2curves::{bn256::Fr, group::ff::PrimeField};

	#[test]
	fn test_add_same_point() {
		// Testing addition operation with identical points.
		let p: PointProjective<Fr, BabyJubJub> = PointProjective {
			x: Fr::from_str_vartime(
				"17777552123799933955779906779655732241715742912184938656739573121738514868268",
			)
			.unwrap(),
			y: Fr::from_str_vartime(
				"2626589144620713026669568689430873010625803728049924121243784502389097019475",
			)
			.unwrap(),
			z: Fr::one(),
			_p: PhantomData,
		};

		let q: PointProjective<Fr, BabyJubJub> = PointProjective {
			x: Fr::from_str_vartime(
				"17777552123799933955779906779655732241715742912184938656739573121738514868268",
			)
			.unwrap(),
			y: Fr::from_str_vartime(
				"2626589144620713026669568689430873010625803728049924121243784502389097019475",
			)
			.unwrap(),
			z: Fr::one(),
			_p: PhantomData,
		};

		let res = p.add(&q).affine();
		assert_eq!(
			res.x,
			Fr::from_str_vartime(
				"6890855772600357754907169075114257697580319025794532037257385534741338397365"
			)
			.unwrap(),
		);
		assert_eq!(
			res.y,
			Fr::from_str_vartime(
				"4338620300185947561074059802482547481416142213883829469920100239455078257889"
			)
			.unwrap(),
		);
	}

	#[test]
	fn test_add_different_points() {
		// Testing addition operation with different points.
		let p: PointProjective<Fr, BabyJubJub> = PointProjective {
			x: Fr::from_str_vartime(
				"17777552123799933955779906779655732241715742912184938656739573121738514868268",
			)
			.unwrap(),
			y: Fr::from_str_vartime(
				"2626589144620713026669568689430873010625803728049924121243784502389097019475",
			)
			.unwrap(),
			z: Fr::one(),
			_p: PhantomData,
		};

		let q: PointProjective<Fr, BabyJubJub> = PointProjective {
			x: Fr::from_str_vartime(
				"16540640123574156134436876038791482806971768689494387082833631921987005038935",
			)
			.unwrap(),
			y: Fr::from_str_vartime(
				"20819045374670962167435360035096875258406992893633759881276124905556507972311",
			)
			.unwrap(),
			z: Fr::one(),
			_p: PhantomData,
		};

		let res = p.add(&q).affine();
		assert_eq!(
			res.x,
			Fr::from_str_vartime(
				"7916061937171219682591368294088513039687205273691143098332585753343424131937"
			)
			.unwrap(),
		);
		assert_eq!(
			res.y,
			Fr::from_str_vartime(
				"14035240266687799601661095864649209771790948434046947201833777492504781204499"
			)
			.unwrap(),
		);
	}

	#[test]
	fn test_mul_scalar() {
		// Testing scalar multiplication operation.
		let p: Point<Fr, BabyJubJub> = Point {
			x: Fr::from_str_vartime(
				"17777552123799933955779906779655732241715742912184938656739573121738514868268",
			)
			.unwrap(),
			y: Fr::from_str_vartime(
				"2626589144620713026669568689430873010625803728049924121243784502389097019475",
			)
			.unwrap(),
			_p: PhantomData,
		};
		let res_m = p.mul_scalar(Fr::from(3)).affine();
		let res_a = p.projective().add(&p.projective());
		let res_a = res_a.add(&p.projective()).affine();
		assert_eq!(res_m.x, res_a.x);

		assert_eq!(
			res_m.x,
			Fr::from_str_vartime(
				"19372461775513343691590086534037741906533799473648040012278229434133483800898"
			)
			.unwrap(),
		);
		assert_eq!(
			res_m.y,
			Fr::from_str_vartime(
				"9458658722007214007257525444427903161243386465067105737478306991484593958249"
			)
			.unwrap(),
		);

		let n = Fr::from_str_vartime(
			"14035240266687799601661095864649209771790948434046947201833777492504781204499",
		)
		.unwrap();
		let res2 = p.mul_scalar(n).affine();
		assert_eq!(
			res2.x,
			Fr::from_str_vartime(
				"17070357974431721403481313912716834497662307308519659060910483826664480189605"
			)
			.unwrap(),
		);
		assert_eq!(
			res2.y,
			Fr::from_str_vartime(
				"4014745322800118607127020275658861516666525056516280575712425373174125159339"
			)
			.unwrap(),
		);
	}
}
