use super::ed_on_bn254::{A, D};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::Value,
		plonk::{Assigned, Expression},
	},
};

// ADD operation between points `r` and `e`
// add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
pub fn add(r_x: Fr, r_y: Fr, r_z: Fr, e_x: Fr, e_y: Fr, e_z: Fr) -> (Fr, Fr, Fr) {
	// A = Z1*Z2
	let a = r_z.mul(&e_z);
	// B = A^2
	let b = a.square();
	// C = X1*X2
	let c = r_x.mul(&e_x);
	// D = Y1*Y2
	let d = r_y.mul(&e_y);
	// E = d*C*D
	let e = D.mul(&c).mul(&d);
	// F = B-E
	let f = b.sub(&e);
	// G = B+E
	let g = b.add(&e);
	// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
	let x3 = a.mul(&f).mul(&r_x.add(&r_y).mul(&e_x.add(&e_y)).sub(&c).sub(&d));
	// Y3 = A*G*(D-a*C)
	let y3 = a.mul(&g).mul(&d.sub(&A.mul(&c)));
	// Z3 = F*G
	let z3 = f.mul(&g);

	(x3, y3, z3)
}

pub fn add_exp(
	r_x: Expression<Fr>, r_y: Expression<Fr>, r_z: Expression<Fr>, e_x: Expression<Fr>,
	e_y: Expression<Fr>, e_z: Expression<Fr>,
) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
	let const_d = Expression::Constant(D);
	let const_a = Expression::Constant(A);
	// A = Z1*Z2
	let r_a = r_z.clone() * e_z.clone();
	// B = A^2
	let r_b = r_a.clone().square();
	// C = X1*X2
	let r_c = r_x.clone() * e_x.clone();
	// D = Y1*Y2
	let r_d = r_y.clone() * e_y.clone();
	// E = d*C*D
	let r_e = const_d * r_c.clone() * r_d.clone();
	// F = B-E
	let r_f = r_b.clone() - r_e.clone();
	// G = B+E
	let r_g = r_b + r_e;
	// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
	let r_x3 = r_a.clone()
		* r_f.clone()
		* ((r_x.clone() + r_y.clone()) * (e_x.clone() + e_y.clone()) - r_c.clone() - r_d.clone());
	// Y3 = A*G*(D-a*C)
	let r_y3 = r_a * r_g.clone() * (r_d - const_a.clone() * r_c);
	// Z3 = F*G
	let r_z3 = r_f * r_g;
	(r_x3, r_y3, r_z3)
}

pub fn add_value(
	r_x: Value<Assigned<Fr>>, r_y: Value<Assigned<Fr>>, r_z: Value<Assigned<Fr>>,
	e_x: Value<Assigned<Fr>>, e_y: Value<Assigned<Fr>>, e_z: Value<Assigned<Fr>>,
) -> (
	Value<Assigned<Fr>>,
	Value<Assigned<Fr>>,
	Value<Assigned<Fr>>,
) {
	let const_a = Value::known(Assigned::from(A));
	let const_d = Value::known(Assigned::from(D));
	// Add `r` and `e`
	// A = Z1*Z2
	let r_a = r_z * e_z;
	// B = A^2
	let r_b = r_a.to_field().square();
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

// DOUBLE operation of point `e`
// dbl-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
pub fn double(e_x: Fr, e_y: Fr, e_z: Fr) -> (Fr, Fr, Fr) {
	// B = (X1+Y1)^2
	let b = e_x.add(&e_y).square();
	// C = X1^2
	let c = e_x.square();
	// D = Y1^2
	let d = e_y.square();
	// E = a*C
	let e = A.mul(&c);
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

pub fn double_exp(
	e_x: Expression<Fr>, e_y: Expression<Fr>, e_z: Expression<Fr>,
) -> (Expression<Fr>, Expression<Fr>, Expression<Fr>) {
	let const_a = Expression::Constant(A);
	// B = (X1+Y1)^2
	let e_b = (e_x.clone() + e_y.clone()).square();
	// C = X1^2
	let e_c = e_x.square();
	// D = Y1^2
	let e_d = e_y.square();
	// E = a*C
	let e_e = const_a * e_c.clone();
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

pub fn double_value(
	e_x: Value<Assigned<Fr>>, e_y: Value<Assigned<Fr>>, e_z: Value<Assigned<Fr>>,
) -> (
	Value<Assigned<Fr>>,
	Value<Assigned<Fr>>,
	Value<Assigned<Fr>>,
) {
	let const_a = Value::known(Assigned::from(A));
	// B = (X1+Y1)^2
	let e_b = (e_x + e_y).square();
	// C = X1^2
	let e_c = e_x.square();
	// D = Y1^2
	let e_d = e_y.square();
	// E = a*C
	let e_e = const_a * e_c;
	// F = E+D
	let e_f = e_e + e_d;
	// H = Z1^2
	let e_h = e_z.square();
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
