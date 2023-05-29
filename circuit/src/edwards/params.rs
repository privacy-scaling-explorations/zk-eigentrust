use crate::FieldExt;
use halo2::{circuit::Value, halo2curves::bn256::Fr, plonk::Expression};

/// Trait for defining point A and D for Edward curves
pub trait EdwardsParams<F: FieldExt> {
	/// Returns A value
	fn a() -> F;
	/// Returns D value
	fn d() -> F;
	/// Returns B8 point
	fn b8() -> (F, F);
	/// Returns G point
	fn g() -> (F, F);
	/// Returns suborder
	fn suborder() -> F;
	/// Suborder field size in bits
	fn suborder_size() -> usize;
	/// Performs Add operation
	fn add(r_x: F, r_y: F, r_z: F, e_x: F, e_y: F, e_z: F) -> (F, F, F);
	/// Performs Add operation on Expression
	fn add_exp(
		r_x: Expression<F>, r_y: Expression<F>, r_z: Expression<F>, e_x: Expression<F>,
		e_y: Expression<F>, e_z: Expression<F>,
	) -> (Expression<F>, Expression<F>, Expression<F>);
	/// Performs Add operation on Value
	fn add_value(
		r_x: Value<F>, r_y: Value<F>, r_z: Value<F>, e_x: Value<F>, e_y: Value<F>, e_z: Value<F>,
	) -> (Value<F>, Value<F>, Value<F>);
	/// Performs Double operation
	fn double(e_x: F, e_y: F, e_z: F) -> (F, F, F);
	/// Performs Double operation on Expression
	fn double_exp(
		e_x: Expression<F>, e_y: Expression<F>, e_z: Expression<F>,
	) -> (Expression<F>, Expression<F>, Expression<F>);
	/// Performs Double operation on Value
	fn double_value(e_x: Value<F>, e_y: Value<F>, e_z: Value<F>) -> (Value<F>, Value<F>, Value<F>);
}

/// Struct for defining BabyJubJub A and D points
#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BabyJubJub;

impl EdwardsParams<Fr> for BabyJubJub {
	fn a() -> Fr {
		Fr::from_raw([0x292FC, 0x00, 0x00, 0x00])
	}

	fn d() -> Fr {
		Fr::from_raw([0x292F8, 0x00, 0x00, 0x00])
	}

	fn b8() -> (Fr, Fr) {
		(
			Fr::from_raw([
				0x2893F3F6BB957051, 0x2AB8D8010534E0B6, 0x4EACB2E09D6277C1, 0xBB77A6AD63E739B,
			]),
			Fr::from_raw([
				0x4B3C257A872D7D8B, 0xFCE0051FB9E13377, 0x25572E1CD16BF9ED, 0x25797203F7A0B249,
			]),
		)
	}

	fn g() -> (Fr, Fr) {
		(
			Fr::from_raw([
				0x40F41A59F4D4B45E, 0xB494B1255B1162BB, 0x38BCBA38F25645AD, 0x23343E3445B673D,
			]),
			Fr::from_raw([
				0x50F87D64FC000001, 0x4A0CFA121E6E5C24, 0x6E14116DA0605617, 0xC19139CB84C680A,
			]),
		)
	}

	fn suborder() -> Fr {
		Fr::from_raw([
			0x677297DC392126F1, 0xAB3EEDB83920EE0A, 0x370A08B6D0302B0B, 0x60C89CE5C263405,
		])
	}

	fn suborder_size() -> usize {
		252
	}

	/// ADD operation between points `r` and `e`
	// add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
	fn add(r_x: Fr, r_y: Fr, r_z: Fr, e_x: Fr, e_y: Fr, e_z: Fr) -> (Fr, Fr, Fr) {
		let const_d = Self::d();
		let const_a = Self::a();
		// A = Z1*Z2
		let a = r_z.mul(&e_z);
		// B = A^2
		let b = a.square();
		// C = X1*X2
		let c = r_x.mul(&e_x);
		// D = Y1*Y2
		let d = r_y.mul(&e_y);
		// E = d*C*D
		let e = const_d.mul(&c).mul(&d);
		// F = B-E
		let f = b.sub(&e);
		// G = B+E
		let g = b.add(&e);
		// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
		let x3 = a.mul(&f).mul(&r_x.add(&r_y).mul(&e_x.add(&e_y)).sub(&c).sub(&d));
		// Y3 = A*G*(D-a*C)
		let y3 = a.mul(&g).mul(&d.sub(&const_a.mul(&c)));
		// Z3 = F*G
		let z3 = f.mul(&g);

		(x3, y3, z3)
	}

	/// ADD operation between expressions `r` and `e`
	fn add_exp(
		r_x: Expression<Fr>, r_y: Expression<Fr>, r_z: Expression<Fr>, e_x: Expression<Fr>,
		e_y: Expression<Fr>, e_z: Expression<Fr>,
	) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
		let const_d = Self::d();
		let const_a = Self::a();
		// A = Z1*Z2
		let r_a = r_z * e_z;
		// B = A^2
		let r_b = r_a.clone().square();
		// C = X1*X2
		let r_c = r_x.clone() * e_x.clone();
		// D = Y1*Y2
		let r_d = r_y.clone() * e_y.clone();
		// E = d*C*D
		let r_e = r_c.clone() * r_d.clone() * const_d;
		// F = B-E
		let r_f = r_b.clone() - r_e.clone();
		// G = B+E
		let r_g = r_b + r_e;
		// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
		let r_x3 =
			r_a.clone() * r_f.clone() * ((r_x + r_y) * (e_x + e_y) - r_c.clone() - r_d.clone());
		// Y3 = A*G*(D-a*C)
		let r_y3 = r_a * r_g.clone() * (r_d - r_c * const_a.clone());
		// Z3 = F*G
		let r_z3 = r_f * r_g;
		(r_x3, r_y3, r_z3)
	}

	/// ADD operation between assigned values `r` and `e`
	fn add_value(
		r_x: Value<Fr>, r_y: Value<Fr>, r_z: Value<Fr>, e_x: Value<Fr>, e_y: Value<Fr>,
		e_z: Value<Fr>,
	) -> (Value<Fr>, Value<Fr>, Value<Fr>) {
		let const_d = Value::known(Self::d());
		let const_a = Value::known(Self::a());
		// Add `r` and `e`
		// A = Z1*Z2
		let r_a = r_z * e_z;
		// B = A^2
		let r_b = r_a * r_a;
		// C = X1*X2
		let r_c = r_x * e_x;
		// D = Y1*Y2
		let r_d = r_y * e_y;
		// E = d*C*D
		let r_e = const_d * r_c * r_d;
		// F = B-E
		let r_f = r_b - r_e;
		// G = B+E
		let r_g = r_b + r_e;
		// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
		let r_x3 = r_a * r_f * ((r_x + r_y) * (e_x + e_y) - r_c - r_d);
		// Y3 = A*G*(D-a*C)
		let r_y3 = r_a * r_g * (r_d - const_a * r_c);
		// Z3 = F*G
		let r_z3 = r_f * r_g;

		(r_x3, r_y3, r_z3)
	}

	/// DOUBLE operation of point `e`
	// dbl-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
	fn double(e_x: Fr, e_y: Fr, e_z: Fr) -> (Fr, Fr, Fr) {
		let const_a = Self::a();
		// B = (X1+Y1)^2
		let b = e_x.add(&e_y).square();
		// C = X1^2
		let c = e_x.square();
		// D = Y1^2
		let d = e_y.square();
		// E = a*C
		let e = const_a.mul(&c);
		// F = E+D
		let f = e.add(&d);
		// H = Z1^2
		let h = e_z.square();
		// J = F-2*H
		let j = f.sub(&h.double());
		// X3 = (B-C-D)*J
		let x3 = b.sub(&c).sub(&d).mul(&j);
		// Y3 = F*(E-D)
		let y3 = f.mul(&e.sub(&d));
		// Z3 = F*J
		let z3 = f.mul(&j);

		(x3, y3, z3)
	}

	/// DOUBLE operation of expression `e`
	fn double_exp(
		e_x: Expression<Fr>, e_y: Expression<Fr>, e_z: Expression<Fr>,
	) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
		let const_a = Self::a();
		// B = (X1+Y1)^2
		let e_b = (e_x.clone() + e_y.clone()).square();
		// C = X1^2
		let e_c = e_x.square();
		// D = Y1^2
		let e_d = e_y.square();
		// E = a*C
		let e_e = e_c.clone() * const_a;
		// F = E+D
		let e_f = e_e.clone() + e_d.clone();
		// H = Z1^2
		let e_h = e_z.square();
		// J = F-2*H
		let e_j = e_f.clone() - (e_h.clone() + e_h);
		// X3 = (B-C-D)*J
		let e_x3 = (e_b - e_c - e_d.clone()) * e_j.clone();
		// Y3 = F*(E-D)
		let e_y3 = e_f.clone() * (e_e - e_d);
		// Z3 = F*J
		let e_z3 = e_f * e_j;

		(e_x3, e_y3, e_z3)
	}

	/// DOUBLE operation of assigned value `e`
	fn double_value(
		e_x: Value<Fr>, e_y: Value<Fr>, e_z: Value<Fr>,
	) -> (Value<Fr>, Value<Fr>, Value<Fr>) {
		let const_a = Value::known(Self::a());
		// B = (X1+Y1)^2
		let e_b = e_x + e_y;
		let e_b = e_b * e_b;
		// C = X1^2
		let e_c = e_x * e_x;
		// D = Y1^2
		let e_d = e_y * e_y;
		// E = a*C
		let e_e = const_a * e_c;
		// F = E+D
		let e_f = e_e + e_d;
		// H = Z1^2
		let e_h = e_z * e_z;
		// J = F-2*H
		let e_j = e_f - (e_h + e_h);
		// X3 = (B-C-D)*J
		let e_x3 = (e_b - e_c - e_d) * e_j;
		// Y3 = F*(E-D)
		let e_y3 = e_f * (e_e - e_d);
		// Z3 = F*J
		let e_z3 = e_f * e_j;

		(e_x3, e_y3, e_z3)
	}
}
