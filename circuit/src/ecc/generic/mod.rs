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
    type Config = EccAddConfig;
    type Output = AssignedPoint<C, NUM_LIMBS, NUM_BITS, P>;
    fn synthesize(
        self, common: &CommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
    ) -> Result<Self::Output, Error> {
        // Implement the synthesis method
        ...
    }
}
/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccAddConfig {
    /// Constructs selectors from different circuits.
    integer_reduce_selector: Selector,
    integer_sub_selector: Selector,
    integer_mul_selector: Selector,
    integer_div_selector: Selector,
}
impl EccAddConfig {
    /// Construct a new config given the selector of child chips
    pub fn new(
        integer_reduce_selector: Selector, integer_sub_selector: Selector,
        integer_mul_selector: Selector, integer_div_selector: Selector,
    ) -> Self {
        Self {
            integer_reduce_selector,
            integer_sub_selector,
            integer_mul_selector,
            integer_div_selector,
        }
    }
}
