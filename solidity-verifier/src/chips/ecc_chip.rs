use super::scalar_chip::{SolidityFieldChip, SolidityFieldExpr};
use crate::code_generator::ctx::{Expression, SolidityCodeGeneratorContext, Type};
use halo2_ecc_circuit_lib::utils::bn_to_field;
use halo2_ecc_circuit_lib::utils::field_to_bn;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use halo2curves::group::ff::PrimeField;
use halo2curves::group::Curve;
use num_bigint::BigUint;
use std::{marker::PhantomData, rc::Rc};

pub fn get_xy_from_point<C: CurveAffine>(point: C::CurveExt) -> (BigUint, BigUint) {
    let coordinates = point.to_affine().coordinates();
    let x = coordinates.map(|v| *v.x()).unwrap_or(C::Base::zero());
    let y = coordinates.map(|v| *v.y()).unwrap_or(C::Base::zero());
    // let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());
    (field_to_bn(&x), field_to_bn(&y))
}

#[derive(Debug, Clone)]
pub struct SolidityEccExpr<C> {
    pub expr: Rc<Expression>,
    pub v: C,
    is_const: bool,
}

pub(crate) struct SolidityEccChip<C: CurveAffine, E> {
    _c: PhantomData<C>,
    _e: PhantomData<E>,
}

impl<C: CurveAffine, E> SolidityEccChip<C, E> {
    pub fn new() -> Self {
        Self {
            _c: PhantomData,
            _e: PhantomData,
        }
    }
}

impl<C: CurveAffine, E> ArithCommonChip for SolidityEccChip<C, E> {
    type Context = SolidityCodeGeneratorContext;
    type Value = C;
    type AssignedValue = SolidityEccExpr<C::CurveExt>;
    type Error = E;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let v = a.v + b.v;

        if a.is_const && b.is_const {
            return self.assign_const(ctx, v.to_affine());
        }

        let r = Expression::Add(a.expr.clone(), b.expr.clone(), Type::Point);
        let l = ctx.assign_memory(
            r,
            vec![
                field_to_bn(v.to_affine().coordinates().unwrap().x()),
                field_to_bn(v.to_affine().coordinates().unwrap().y()),
            ],
        );

        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: l,
            v,
            is_const: a.is_const && b.is_const,
        })
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let v = a.v - b.v;

        if a.is_const && b.is_const {
            return self.assign_const(ctx, v.to_affine());
        }

        let r = Expression::Sub(a.expr.clone(), b.expr.clone(), Type::Point);
        let l = ctx.assign_memory(
            r,
            vec![
                field_to_bn(v.to_affine().coordinates().unwrap().x()),
                field_to_bn(v.to_affine().coordinates().unwrap().y()),
            ],
        );

        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: l,
            v,
            is_const: a.is_const && b.is_const,
        })
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, C::identity())
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, C::generator())
    }

    fn assign_const(
        &self,
        _ctx: &mut Self::Context,
        c: C,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let (x, y) = get_xy_from_point::<C>(c.to_curve());
        let r = Expression::Point(x, y);
        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: Rc::new(r),
            v: c.to_curve(),
            is_const: true,
        })
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: C,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let (x, y) = get_xy_from_point::<C>(v.to_curve());
        let x: C::Scalar = bn_to_field(&x);
        let y: C::Scalar = bn_to_field(&y);
        let bytes_x = x.to_repr();
        let bytes_y = y.to_repr();
        assert_eq!(bytes_x.as_ref().len(), 32);
        assert_eq!(bytes_y.as_ref().len(), 32);
        let l = if ctx.transcript_context {
            ctx.new_transcript_var(Type::Point, 2)
        } else if ctx.instance_context {
            ctx.new_instance_var(Type::Point, 2)
        } else {
            ctx.extend_var_buf(bytes_x.as_ref());
            ctx.extend_var_buf(bytes_y.as_ref());
            ctx.new_tmp_var(Type::Point, 2)
        };

        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: l,
            v: v.to_curve(),
            is_const: false,
        })
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<C, Self::Error> {
        Ok(v.v.to_affine())
    }

    fn normalize(
        &self,
        _ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v.clone())
    }
}

impl<C: CurveAffine, E> ArithEccChip for SolidityEccChip<C, E> {
    type Point = C;
    type AssignedPoint = SolidityEccExpr<C::CurveExt>;
    type Scalar = C::ScalarExt;
    type AssignedScalar = SolidityFieldExpr<C::ScalarExt>;
    type Native = C::ScalarExt;
    type AssignedNative = SolidityFieldExpr<C::ScalarExt>;

    type ScalarChip = SolidityFieldChip<C::ScalarExt, E>;
    type NativeChip = SolidityFieldChip<C::ScalarExt, E>;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        let v = rhs.v * lhs.v;

        if lhs.is_const && rhs.is_const {
            return self.assign_const(ctx, v.to_affine());
        }

        let r = Expression::Mul(lhs.expr.clone(), rhs.expr.clone(), Type::Point);
        let l = ctx.assign_memory(
            r,
            vec![
                field_to_bn(v.to_affine().coordinates().unwrap().x()),
                field_to_bn(v.to_affine().coordinates().unwrap().y()),
            ],
        );

        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: l,
            v,
            is_const: lhs.is_const && rhs.is_const,
        })
    }

    fn scalar_mul_constant(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: Self::Point,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        let v = rhs * lhs.v;

        if lhs.is_const {
            return self.assign_const(ctx, v.to_affine());
        }

        let (x, y) = get_xy_from_point::<C>(rhs.to_curve());
        let rhs = Expression::Point(x, y);
        let r = Expression::Mul(lhs.expr.clone(), Rc::new(rhs), Type::Point);
        let l = ctx.assign_memory(
            r,
            vec![
                field_to_bn(v.to_affine().coordinates().unwrap().x()),
                field_to_bn(v.to_affine().coordinates().unwrap().y()),
            ],
        );

        Ok(SolidityEccExpr::<C::CurveExt> {
            expr: l,
            v,
            is_const: lhs.is_const,
        })
    }
}
