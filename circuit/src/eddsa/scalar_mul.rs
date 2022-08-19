use super::native::ed_on_bn254::{A, D};
use crate::gadgets::bits2num::{Bits2NumChip, Bits2NumConfig};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region, Value},
		plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, Selector},
		poly::Rotation,
	},
};

pub struct ScalarMulConfig {
	bits2num: Bits2NumConfig,
	bits: Column<Advice>,
	r_x: Column<Advice>,
	r_y: Column<Advice>,
	r_z: Column<Advice>,
	e_x: Column<Advice>,
	e_y: Column<Advice>,
	e_z: Column<Advice>,
	selector: Selector,
}

#[derive(Clone)]
pub struct ScalarMulChip {
	e_x: AssignedCell<Fr, Fr>,
	e_y: AssignedCell<Fr, Fr>,
	e_z: AssignedCell<Fr, Fr>,
	value: AssignedCell<Fr, Fr>,
	value_bits: [Fr; 256],
}

impl ScalarMulChip {
	pub fn new(
		e_x: AssignedCell<Fr, Fr>,
		e_y: AssignedCell<Fr, Fr>,
		e_z: AssignedCell<Fr, Fr>,
		value: AssignedCell<Fr, Fr>,
		value_bits: [Fr; 256],
	) -> Self {
		Self {
			e_x,
			e_y,
			e_z,
			value,
			value_bits,
		}
	}
}

impl ScalarMulChip {
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> ScalarMulConfig {
		let bits2num = Bits2NumChip::configure(meta);
		let bits = meta.advice_column();
		let r_x = meta.advice_column();
		let r_y = meta.advice_column();
		let r_z = meta.advice_column();
		let e_x = meta.advice_column();
		let e_y = meta.advice_column();
		let e_z = meta.advice_column();
		let s = meta.selector();

		meta.create_gate("scalar_mul", |v_cells| {
			let const_d = Expression::Constant(D);
			let const_a = Expression::Constant(A);

			let s_exp = v_cells.query_selector(s);
			let bit_exp = v_cells.query_advice(bits, Rotation::cur());

			let r_x_exp = v_cells.query_advice(r_x, Rotation::cur());
			let r_y_exp = v_cells.query_advice(r_y, Rotation::cur());
			let r_z_exp = v_cells.query_advice(r_z, Rotation::cur());

			let e_x_exp = v_cells.query_advice(e_x, Rotation::cur());
			let e_y_exp = v_cells.query_advice(e_y, Rotation::cur());
			let e_z_exp = v_cells.query_advice(e_z, Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(r_x, Rotation::next());
			let r_y_next_exp = v_cells.query_advice(r_y, Rotation::next());
			let r_z_next_exp = v_cells.query_advice(r_z, Rotation::next());

			let e_x_next_exp = v_cells.query_advice(e_x, Rotation::next());
			let e_y_next_exp = v_cells.query_advice(e_y, Rotation::next());
			let e_z_next_exp = v_cells.query_advice(e_z, Rotation::next());

			// ADD operation between points `r` and `e`
			// add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
			// A = Z1*Z2
			let r_a = r_z_exp.clone() * e_z_exp.clone();
			// B = A^2
			let r_b = r_a.clone().square();
			// C = X1*X2
			let r_c = r_x_exp.clone() * e_x_exp.clone();
			// D = Y1*Y2
			let r_d = r_y_exp.clone() * e_y_exp.clone();
			// E = d*C*D
			let r_e = const_d * r_c.clone() * r_d.clone();
			// F = B-E
			let r_f = r_b.clone() - r_e.clone();
			// G = B+E
			let r_g = r_b + r_e;
			// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
			let r_x3 = r_a.clone()
				* r_f.clone() * ((r_x_exp.clone() + r_y_exp.clone())
				* (e_x_exp.clone() + e_y_exp.clone())
				- r_c.clone() - r_d.clone());
			// Y3 = A*G*(D-a*C)
			let r_y3 = r_a * r_g.clone() * (r_d - const_a.clone() * r_c);
			// Z3 = F*G
			let r_z3 = r_f * r_g;

			// DOUBLE operation of point `e`
			// dbl-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
			// B = (X1+Y1)^2
			let e_b = (e_x_exp.clone() + e_y_exp.clone()).square();
			// C = X1^2
			let e_c = e_x_exp.square();
			// D = Y1^2
			let e_d = e_y_exp.square();
			// E = a*C
			let e_e = const_a * e_c.clone();
			// F = E+D
			let e_f = e_e.clone() + e_d.clone();
			// H = Z1^2
			let e_h = e_z_exp.square();
			// J = F-2*H
			let e_j = e_f.clone() - (e_h.clone() + e_h);
			// X3 = (B-C-D)*J
			let e_x3 = (e_b - e_c - e_d.clone()) * e_j.clone();
			// Y3 = F*(E-D)
			let e_y3 = e_f.clone() * (e_e - e_d);
			// Z3 = F*J
			let e_z3 = e_f * e_j;

			// Select the next value based on a `bit` -- see `select` gadget.
			let selected_r_x =
				bit_exp.clone() * (r_x_exp - r_x3.clone()) - (r_x_next_exp.clone() - r_x3.clone());
			let selected_r_y =
				bit_exp.clone() * (r_y_exp - r_y3.clone()) - (r_y_next_exp.clone() - r_y3.clone());
			let selected_r_z =
				bit_exp.clone() * (r_z_exp - r_z3.clone()) - (r_z_next_exp.clone() - r_z3.clone());

			vec![
				// Ensure the point addition of `r` and `e` is properly calculated
				s_exp.clone() * selected_r_x,
				s_exp.clone() * selected_r_y,
				s_exp.clone() * selected_r_z,
				// Ensure the `e` doubling is properly calculated
				s_exp.clone() * (e_x_next_exp - e_x3),
				s_exp.clone() * (e_y_next_exp - e_y3),
				s_exp * (e_z_next_exp - e_z3),
			]
		});

		ScalarMulConfig {
			bits2num,
			bits,
			r_x,
			r_y,
			r_z,
			e_x,
			e_y,
			e_z,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: ScalarMulConfig,
		mut layouter: impl Layouter<Fr>,
	) -> Result<(), Error> {
		let bits2num = Bits2NumChip::new(self.value.clone(), self.value_bits);
		let bits = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;

		layouter.assign_region(
			|| "scalar_mul",
			|mut region: Region<'_, Fr>| {
				for i in 0..bits.len() {
					bits[i].copy_advice(|| "bit", &mut region, config.bits, i)?;
				}

				let const_a = Value::known(Assigned::from(A));
				let const_d = Value::known(Assigned::from(D));
				let mut r_x =
					region.assign_advice_from_constant(|| "r_x_0", config.r_x, 0, Fr::zero())?;
				let mut r_y =
					region.assign_advice_from_constant(|| "r_y_0", config.r_y, 0, Fr::one())?;
				let mut r_z =
					region.assign_advice_from_constant(|| "r_z_0", config.r_z, 0, Fr::one())?;

				let mut e_x = self.e_x.copy_advice(|| "e_x", &mut region, config.e_x, 0)?;
				let mut e_y = self.e_y.copy_advice(|| "e_y", &mut region, config.e_y, 0)?;
				let mut e_z = self.e_z.copy_advice(|| "e_z", &mut region, config.e_z, 0)?;

				for i in 0..self.value_bits.len() {
					config.selector.enable(&mut region, i)?;

					// Add `r` and `e`
					// A = Z1*Z2
					let r_a = r_z.value_field() * e_z.value_field();
					// B = A^2
					let r_b = r_a.square();
					// C = X1*X2
					let r_c = r_x.value_field() * e_x.value_field();
					// D = Y1*Y2
					let r_d = r_y.value_field() * e_y.value_field();
					// E = d*C*D
					let r_e = const_d * r_c * r_d;
					// F = B-E
					let r_f = r_b - r_e;
					// G = B+E
					let r_g = r_b + r_e;
					// X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
					let r_x3 = r_a
						* r_f * ((r_x.value_field() + r_y.value_field())
						* (e_x.value_field() + e_y.value_field())
						- r_c - r_d);
					// Y3 = A*G*(D-a*C)
					let r_y3 = r_a * r_g * (r_d - const_a * r_c);
					// Z3 = F*G
					let r_z3 = r_f * r_g;

					// Double `e`
					// B = (X1+Y1)^2
					let e_b = (e_x.value_field() + e_y.value_field()).square();
					// C = X1^2
					let e_c = e_x.value_field().square();
					// D = Y1^2
					let e_d = e_y.value_field().square();
					// E = a*C
					let e_e = const_a.to_field() * e_c;
					// F = E+D
					let e_f = e_e + e_d;
					// H = Z1^2
					let e_h = e_z.value_field().square();
					// J = F-2*H
					let e_j = e_f - (e_h + e_h);
					// X3 = (B-C-D)*J
					let e_x3 = (e_b - e_c - e_d) * e_j;
					// Y3 = F*(E-D)
					let e_y3 = e_f * (e_e - e_d);
					// Z3 = F*J
					let e_z3 = e_f * e_j;

					let (r_x_next, r_y_next, r_z_next) = if self.value_bits[i] == Fr::one() {
						(r_x3, r_y3, r_z3)
					} else {
						(r_x.value_field(), r_y.value_field(), r_z.value_field())
					};

					r_x = region.assign_advice(
						|| "r_x",
						config.r_x,
						i + 1,
						|| r_x_next.evaluate(),
					)?;
					r_y = region.assign_advice(
						|| "r_y",
						config.r_y,
						i + 1,
						|| r_y_next.evaluate(),
					)?;
					r_z = region.assign_advice(
						|| "r_z",
						config.r_z,
						i + 1,
						|| r_z_next.evaluate(),
					)?;

					e_x = region.assign_advice(|| "e_x", config.e_x, i + 1, || e_x3.evaluate())?;
					e_y = region.assign_advice(|| "e_y", config.e_y, i + 1, || e_y3.evaluate())?;
					e_z = region.assign_advice(|| "e_z", config.e_z, i + 1, || e_z3.evaluate())?;
				}

				Ok(())
			},
		)
	}
}

#[cfg(test)]
mod test {

	#[test]
	fn should_mul_point_with_scalar() {}

	#[test]
	fn should_mul_point_with_scalar_production() {}
}
