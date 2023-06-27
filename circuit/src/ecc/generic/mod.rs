pub struct EccAddChipset<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
    P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
    C::Base: FieldExt,
    C::Scalar: FieldExt,
{
    p: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
    q: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
}
impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset for EccAddChipset<C, N, NUM_LIMBS, NUM_BITS, P>
where
    P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
    C::Base: FieldExt,
    C::Scalar: FieldExt,
{
    type Config = ...;
    type Output = ...;
    fn synthesize(
        self, common: &CommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
    ) -> Result<Self::Output, Error> {
        // Implement the synthesis method
        ...
    }
}
