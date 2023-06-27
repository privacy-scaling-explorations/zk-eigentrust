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
    // Implementation goes here
}
