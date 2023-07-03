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

        let r_x_chip = IntegerSubChip::new(r_x, q_x_reduced);
        let r_x = r_x_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "r_x"))?;

        // Calculate the y-coordinate of the resulting point r
        let r_y_chip = IntegerSubChip::new(s * (p_x_reduced - r_x), p_y_reduced);
        let r_y = r_y_chip.synthesize(common, &config.integer_sub_selector, layouter.namespace(|| "r_y"))?;

        // Return the resulting point r
        Ok(AssignedPoint::new(r_x, r_y))
    }
}

