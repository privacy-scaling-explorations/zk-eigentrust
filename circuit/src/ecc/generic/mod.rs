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
