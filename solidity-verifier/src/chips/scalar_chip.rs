use halo2_ecc_circuit_lib::utils::{bn_to_field, field_to_bn};
use halo2_proofs::arithmetic::FieldExt;
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, field::ArithFieldChip};
use num_bigint::ToBigUint;
use std::marker::PhantomData;
use std::rc::Rc;

use crate::code_generator::ctx::{Expression, SolidityCodeGeneratorContext, Type};

#[derive(Debug, Clone)]
pub struct SolidityFieldExpr<F> {
    pub expr: Rc<Expression>,
    pub v: F,
    pub(super) is_const: bool,
}

pub(crate) struct SolidityFieldChip<F: FieldExt, E> {
    _f: PhantomData<F>,
    _e: PhantomData<E>,
}

impl<F: FieldExt, E> SolidityFieldChip<F, E> {
    pub fn new() -> Self {
        Self {
            _f: PhantomData,
            _e: PhantomData,
        }
    }
}

impl<F: FieldExt, E> ArithCommonChip for SolidityFieldChip<F, E> {
    type Context = SolidityCodeGeneratorContext;
    type Value = F;
    type AssignedValue = SolidityFieldExpr<F>;
    type Error = E;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let v = a.v + b.v;

        if a.is_const && b.is_const {
            return self.assign_const(ctx, v);
        }

        if a.is_const && a.v == bn_to_field(&0_u32.to_biguint().unwrap()) {
            return Ok(b.clone());
        }

        if b.is_const && b.v == bn_to_field(&0_u32.to_biguint().unwrap()) {
            return Ok(a.clone());
        }

        let r = Expression::Add(a.expr.clone(), b.expr.clone(), Type::Scalar);
        let l = ctx.assign_memory(r, vec![field_to_bn(&v)]);

        Ok(SolidityFieldExpr::<F> {
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
            return self.assign_const(ctx, v);
        }

        if b.is_const && b.v == bn_to_field(&0_u32.to_biguint().unwrap()) {
            return Ok(a.clone());
        }

        let r = Expression::Sub(a.expr.clone(), b.expr.clone(), Type::Scalar);
        let l = ctx.assign_memory(r, vec![field_to_bn(&v)]);

        Ok(SolidityFieldExpr::<F> {
            expr: l,
            v,
            is_const: a.is_const && b.is_const,
        })
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, bn_to_field(&0_u32.to_biguint().unwrap()))
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, bn_to_field(&1_u32.to_biguint().unwrap()))
    }

    fn assign_const(
        &self,
        _ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let r = Rc::new(Expression::Scalar(field_to_bn(&c)));
        // let l = ctx.assign_memory(r);
        Ok(SolidityFieldExpr::<F> {
            expr: r,
            v: c,
            is_const: true,
        })
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: F,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let l = if ctx.transcript_context {
            ctx.new_transcript_var(Type::Scalar, 1)
        } else if ctx.instance_context {
            ctx.new_instance_var(Type::Scalar, 1)
        } else {
            ctx.extend_var_buf(&[0u8; 1]);
            ctx.new_tmp_var(Type::Scalar, 1)
        };

        Ok(SolidityFieldExpr::<F> {
            expr: l,
            v,
            is_const: false,
        })
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(v.v)
    }

    fn normalize(
        &self,
        _ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v.clone())
    }
}

impl<F: FieldExt, E> ArithFieldChip for SolidityFieldChip<F, E> {
    type Field = F;
    type AssignedField = SolidityFieldExpr<F>;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let v = a.v * b.v;

        if a.is_const && b.is_const {
            return self.assign_const(ctx, v);
        }

        if a.is_const && a.v == bn_to_field(&1_u32.to_biguint().unwrap()) {
            return Ok(b.clone());
        }

        if b.is_const && b.v == bn_to_field(&1_u32.to_biguint().unwrap()) {
            return Ok(a.clone());
        }

        let r = Expression::Mul(a.expr.clone(), b.expr.clone(), Type::Scalar);
        let l = ctx.assign_memory(r, vec![field_to_bn(&v)]);

        Ok(SolidityFieldExpr::<F> {
            expr: l,
            v,
            is_const: a.is_const && b.is_const,
        })
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let v = a.v * b.v.invert().unwrap();

        if a.is_const && b.is_const {
            return self.assign_const(ctx, v);
        }

        if b.is_const && b.v == bn_to_field(&1_u32.to_biguint().unwrap()) {
            return Ok(a.clone());
        }

        let r = Expression::Div(a.expr.clone(), b.expr.clone(), Type::Scalar);
        let l = ctx.assign_memory(r, vec![field_to_bn(&v)]);

        Ok(SolidityFieldExpr::<F> {
            expr: l,
            v,
            is_const: a.is_const && b.is_const,
        })
    }

    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let v = a.v * a.v;
        if a.is_const {
            return self.assign_const(ctx, v);
        }

        let r = Expression::Mul(a.expr.clone(), a.expr.clone(), Type::Scalar);
        let l = ctx.assign_memory(r, vec![field_to_bn(&v)]);

        Ok(SolidityFieldExpr::<F> {
            expr: l,
            v,
            is_const: a.is_const,
        })
    }

    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        let mut acc = self.assign_const(ctx, b)?;
        for (x, coeff) in a_with_coeff {
            let coeff = self.assign_const(ctx, coeff)?;
            let m = self.mul(ctx, x, &coeff)?;
            acc = self.add(ctx, &acc, &m)?;
        }
        Ok(acc)
    }

    fn mul_add_constant(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(SolidityFieldExpr::<F> {
            expr: Rc::new(Expression::MulAdd(
                a.expr.clone(),
                b.expr.clone(),
                Rc::new(Expression::Scalar(field_to_bn(&c))),
                Type::Scalar,
            )),
            v: a.v * b.v + c,
            is_const: false,
        })
    }
}
