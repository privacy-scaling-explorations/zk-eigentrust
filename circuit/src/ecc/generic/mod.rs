/// Native implementation
pub mod native;


/// Chipset structure for the EccAdd.
pub struct EccAddChipset<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
    P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
    C::Base: FieldExt,
    C::Scalar: FieldExt,
{
    // Assigned point p
    p: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
    // Assigned point q
    q: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<N>
    for EccAddChipset<C, N, NUM_LIMBS, NUM_BITS, P>
where
    P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
    C::Base: FieldExt,
    C::Scalar: FieldExt,
{
    type Config = EccAddConfig;
    type Output = AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>;

    /// Synthesize the circuit.
    fn synthesize(
        self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
    ) -> Result<Self::Output, Error> {

        // Create instances of the necessary chips
        let p_x_reduce_chip = IntegerReduceChip::new(self.p.x.clone());
        let p_y_reduce_chip = IntegerReduceChip::new(self.p.y.clone());
        let q_x_reduce_chip = IntegerReduceChip::new(self.q.x.clone());
        let q_y_reduce_chip = IntegerReduceChip::new(self.q.y.clone());

        // Perform the necessary operations
        let p_x_reduced = p_x_reduce_chip.synthesize(common, &config.integer_reduce_selector, layouter.namespace(|| "reduce_p_x"))?;
        let p_y_reduced = p_y_reduce_chip.synthesize(common, &config.integer_reduce_selector, layouter.namespace(|| "reduce_p_y"))?;
        let q_x_reduced = q_x_reduce_chip.synthesize(common, &config.integer_reduce_selector, layouter.namespace(|| "reduce_q_x"))?;
        let q_y_reduced = q_y_reduce_chip.synthesize(common, &config.integer_reduce_selector, layouter.namespace(|| "reduce_q_y"))?;

        // Calculate the slope s = (q.y - p.y) / (q.x - p.x)
        let numerator_chip = IntegerSubChip::new(q_y_reduced, p_y_reduced.clone());
        let numerator = numerator_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "numerator"))?;
        let denominator_chip = IntegerSubChip::new(q_x_reduced, p_x_reduced.clone());
        let denominator = denominator_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "denominator"))?;
        let s_chip = IntegerDivChip::new(numerator, denominator);
        let s = s_chip.synthesize(common, &config.integer_div_selector, layouter.namespace(|| "s"))?;
        // Create an instance of IntegerMulChip to multiply `s` by itself
        let s_squared_chip = IntegerMulChip::new(s.clone(), s);
        let s_squared = s_squared_chip.synthesize(common, &config.integer_mul_selector, layouter.namespace(|| "s_squared"))?;
        let r_x_chip = IntegerSubChip::new(s_squared, p_x_reduced.clone());
        let r_x = r_x_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "r_x"))?;
        let sub_chip = IntegerSubChip::new(p_x_reduced, r_x);
        let sub_result = sub_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "sub_result"))?;
        let mul_chip = IntegerMulChip::new(s, sub_result);
        let mul_result = mul_chip.synthesize(common, &config.integer_mul_selector, layouter.namespace(|| "mul_result"))?;
        let r_y_chip = IntegerSubChip::new(mul_result, p_y_reduced);
        let r_y = r_y_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "r_y"))?;

        // Return the resulting point r
        Ok(AssignedPoint::new(r_x, r_y))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use halo2::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand::thread_rng;

    #[test]
    fn test_ecc_add_chipset_synthesize() {
        // Create a mock prover for our tests
        let mut prover = MockProver::<Scalar>::default();

        // Create instances of EccAddChipset with different inputs
        let ecc_add_chipset1 = EccAddChipset::new(/* insert appropriate arguments here */);
        let ecc_add_chipset2 = EccAddChipset::new(/* insert appropriate arguments here */);

        // Call the synthesize method on these instances
        let result1 = ecc_add_chipset1.synthesize(/* insert appropriate arguments here */);
        let result2 = ecc_add_chipset2.synthesize(/* insert appropriate arguments here */);

        // Check the output
        assert_eq!(result1, /* expected output */);
        assert_eq!(result2, /* expected output */);

        // Add additional tests to cover various scenarios and edge cases
        // ...
    }
}

