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
        // Implement the logic for addition of points p and q here
        // ...
    }
}

