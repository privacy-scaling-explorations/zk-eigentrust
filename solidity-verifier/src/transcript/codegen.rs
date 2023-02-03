use crate::chips::ecc_chip::SolidityEccExpr;
use crate::chips::scalar_chip::SolidityFieldExpr;
use crate::code_generator::ctx::SolidityCodeGeneratorContext;
use halo2_ecc_circuit_lib::utils::field_to_bn;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::{Challenge255, Transcript, TranscriptRead};
use halo2_proofs::{arithmetic::CurveAffine, plonk::Error};
use halo2_snark_aggregator_api::arith::common::ArithCommonChip;
use halo2_snark_aggregator_api::transcript::sha::ShaRead;
use halo2_snark_aggregator_api::{
    arith::ecc::ArithEccChip,
    hash::poseidon::PoseidonChip,
    transcript::{encode::Encode, read::TranscriptRead as APITranscriptRead},
};
use halo2curves::group::Curve;
use std::{io, marker::PhantomData};

pub struct CodegenTranscriptRead<
    R: io::Read,
    C: CurveAffine,
    A: ArithEccChip<
        Point = C,
        Scalar = C::Scalar,
        Context = SolidityCodeGeneratorContext,
        AssignedNative = SolidityFieldExpr<C::Scalar>,
        AssignedScalar = SolidityFieldExpr<C::Scalar>,
        AssignedPoint = SolidityEccExpr<C::CurveExt>,
    >,
    E: Encode<A>,
    const T: usize,
    const RATE: usize,
> {
    hash: PoseidonChip<A::NativeChip, T, RATE>,
    reader: ShaRead<R, C, Challenge255<C>, sha3::Keccak256>,
    _phantom: PhantomData<E>,
}

impl<
        R: io::Read,
        C: CurveAffine,
        A: ArithEccChip<
            Point = C,
            Scalar = C::Scalar,
            Context = SolidityCodeGeneratorContext,
            AssignedNative = SolidityFieldExpr<C::Scalar>,
            AssignedScalar = SolidityFieldExpr<C::Scalar>,
            AssignedPoint = SolidityEccExpr<C::CurveExt>,
        >,
        E: Encode<A>,
        const T: usize,
        const RATE: usize,
    > CodegenTranscriptRead<R, C, A, E, T, RATE>
{
    pub fn new(
        reader: R,
        ctx: &mut A::Context,
        schip: &A::NativeChip,
        r_f: usize,
        r_p: usize,
    ) -> Result<CodegenTranscriptRead<R, C, A, E, T, RATE>, A::Error> {
        Ok(CodegenTranscriptRead {
            hash: PoseidonChip::new(ctx, schip, r_f, r_p)?,
            reader: ShaRead::init(reader),
            _phantom: PhantomData,
        })
    }

    fn _common_point(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        pchip: &A,
        p: &A::AssignedPoint,
    ) -> Result<(), A::Error> {
        let encoded = E::encode_point(ctx, nchip, schip, pchip, p)?;
        ctx.update(&p.expr, ctx.absorbing_offset);
        ctx.absorbing_offset += 3;
        // ctx.update(&encoded[1].expr);
        self.hash.update(&encoded);
        Ok(())
    }

    fn _common_scalar(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        s: &A::AssignedScalar,
    ) -> Result<(), A::Error> {
        let encoded = E::encode_scalar(ctx, nchip, schip, s)?;
        ctx.update(&s.expr, ctx.absorbing_offset);
        ctx.absorbing_offset += 2;
        self.hash.update(&encoded);
        Ok(())
    }
}

impl<
        R: io::Read,
        C: CurveAffine,
        A: ArithEccChip<
            Point = C,
            Scalar = C::Scalar,
            Error = Error,
            Context = SolidityCodeGeneratorContext,
            AssignedNative = SolidityFieldExpr<C::Scalar>,
            AssignedScalar = SolidityFieldExpr<C::Scalar>,
            AssignedPoint = SolidityEccExpr<C::CurveExt>,
        >,
        E: Encode<A>,
        const T: usize,
        const RATE: usize,
    > CodegenTranscriptRead<R, C, A, E, T, RATE>
{
}

impl<
        R: io::Read,
        C: CurveAffine,
        A: ArithEccChip<
            Point = C,
            Scalar = C::Scalar,
            Error = Error,
            Context = SolidityCodeGeneratorContext,
            AssignedNative = SolidityFieldExpr<C::Scalar>,
            AssignedScalar = SolidityFieldExpr<C::Scalar>,
            AssignedPoint = SolidityEccExpr<C::CurveExt>,
        >,
        E: Encode<A>,
        const T: usize,
        const RATE: usize,
    > APITranscriptRead<A> for CodegenTranscriptRead<R, C, A, E, T, RATE>
{
    fn read_point(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        pchip: &A,
    ) -> Result<A::AssignedPoint, A::Error> {
        let point = self.reader.read_point()?;
        ctx.enter_transcript();
        let assigned_point = pchip.assign_var(ctx, point)?;
        ctx.exit_transcript();
        self._common_point(ctx, nchip, schip, pchip, &assigned_point)?;

        Ok(assigned_point)
    }

    fn read_constant_point(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        pchip: &A,
    ) -> Result<A::AssignedPoint, A::Error> {
        let point = self.reader.read_point()?;
        let assigned_point = pchip.assign_const(ctx, point)?;

        self._common_point(ctx, nchip, schip, pchip, &assigned_point)?;

        Ok(assigned_point)
    }

    fn read_scalar(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error> {
        let scalar = self.reader.read_scalar()?;
        ctx.enter_transcript();
        let assigned_scalar = schip.assign_var(ctx, scalar)?;
        ctx.exit_transcript();

        self._common_scalar(ctx, nchip, schip, &assigned_scalar)?;

        Ok(assigned_scalar)
    }

    fn read_constant_scalar(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error> {
        let scalar = self.reader.read_scalar()?;
        let assigned_scalar = schip.assign_const(ctx, scalar)?;

        self._common_scalar(ctx, nchip, schip, &assigned_scalar)?;

        Ok(assigned_scalar)
    }

    fn squeeze_challenge_scalar(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error> {
        let scalar: C::Scalar = self.reader.squeeze_challenge().get_scalar();
        ctx.enter_hash();
        let mut v = self.hash.squeeze(ctx, nchip)?;
        let e = ctx.squeeze_challenge_scalar(ctx.absorbing_offset, field_to_bn(&scalar));
        if ctx.max_absorbing_offset < ctx.absorbing_offset {
            ctx.max_absorbing_offset = ctx.absorbing_offset;
        }
        ctx.absorbing_offset = 1;
        v.expr = e;
        v.v = scalar;
        let s = E::decode_scalar(ctx, nchip, schip, &[v])?;
        Ok(s)
    }

    fn common_point(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        pchip: &A,
        p: &A::AssignedPoint,
    ) -> Result<(), A::Error> {
        self._common_point(ctx, nchip, schip, pchip, p)?;
        self.reader.common_point(p.v.to_affine())?;
        Ok(())
    }

    fn common_scalar(
        &mut self,
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        s: &A::AssignedScalar,
    ) -> Result<(), A::Error> {
        self._common_scalar(ctx, nchip, schip, s)?;
        self.reader.common_scalar(s.v)?;
        Ok(())
    }
}
