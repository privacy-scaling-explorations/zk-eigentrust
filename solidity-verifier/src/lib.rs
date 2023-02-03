pub(crate) mod chips;
pub(crate) mod code_generator;
pub(crate) mod transcript;

use crate::chips::{
    ecc_chip::SolidityEccChip, encode_chip::PoseidonEncode, scalar_chip::SolidityFieldChip,
};
use crate::code_generator::aggregate::aggregate;
use crate::code_generator::ctx::SolidityCodeGeneratorContext;
use crate::code_generator::linear_scan::memory_optimize;
use crate::transcript::codegen::CodegenTranscriptRead;
use code_generator::ctx::{CodeGeneratorCtx, G2Point, Statement};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use halo2_snark_aggregator_api::systems::halo2::verify::{
    assign_instance_commitment, verify_single_proof_no_eval,
};
use halo2_snark_aggregator_circuit::fs::{load_target_circuit_params, load_target_circuit_vk};
use halo2_snark_aggregator_circuit::sample_circuit::TargetCircuit;
use halo2curves::bn256::Bn256;
use halo2curves::group::{Curve, Group};
use halo2curves::pairing::{Engine, MillerLoopResult, MultiMillerLoop};
use halo2curves::FieldExt;
use log::info;
use num_bigint::BigUint;
use std::fmt::Debug;
use std::path::PathBuf;
use tera::{Context, Tera};

fn render_verifier_sol_template<C: CurveAffine>(
    args: CodeGeneratorCtx,
    _template_folder: std::path::PathBuf,
) -> String {
    let mut ctx = Context::new();
    let mut opcodes = vec![];
    let mut incremental_ident = 0u64;
    let mut equations = vec![];
    for s in args.assignments {
        equations.append(&mut s.to_solidity_string(&mut opcodes, &mut incremental_ident));
    }
    equations.append(&mut Statement::opcodes_to_solidity_string(&mut opcodes));

    let mut instance_assign = vec![];
    for i in 4..args.instance_size {
        instance_assign.push(format!(
            "instances[{}] = target_circuit_final_pair[{}];",
            i, i
        ))
    }

    ctx.insert("wx", &(args.wx).to_typed_string());
    ctx.insert("wg", &(args.wg).to_typed_string());
    ctx.insert("statements", &equations);
    ctx.insert("instance_assign", &instance_assign);
    ctx.insert(
        "target_circuit_s_g2_x0",
        &args.target_circuit_s_g2.x.0.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_s_g2_x1",
        &args.target_circuit_s_g2.x.1.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_s_g2_y0",
        &args.target_circuit_s_g2.y.0.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_s_g2_y1",
        &args.target_circuit_s_g2.y.1.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_n_g2_x0",
        &args.target_circuit_n_g2.x.0.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_n_g2_x1",
        &args.target_circuit_n_g2.x.1.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_n_g2_y0",
        &args.target_circuit_n_g2.y.0.to_str_radix(10),
    );
    ctx.insert(
        "target_circuit_n_g2_y1",
        &args.target_circuit_n_g2.y.1.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_s_g2_x0",
        &args.verify_circuit_s_g2.x.0.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_s_g2_x1",
        &args.verify_circuit_s_g2.x.1.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_s_g2_y0",
        &args.verify_circuit_s_g2.y.0.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_s_g2_y1",
        &args.verify_circuit_s_g2.y.1.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_n_g2_x0",
        &args.verify_circuit_n_g2.x.0.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_n_g2_x1",
        &args.verify_circuit_n_g2.x.1.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_n_g2_y0",
        &args.verify_circuit_n_g2.y.0.to_str_radix(10),
    );
    ctx.insert(
        "verify_circuit_n_g2_y1",
        &args.verify_circuit_n_g2.y.1.to_str_radix(10),
    );
    ctx.insert("memory_size", &args.memory_size);
    ctx.insert("instance_size", &args.instance_size);
    ctx.insert("absorbing_length", &args.absorbing_length);
    Tera::one_off(include_str!("../templates/verifier.sol"), &ctx, false)
        .expect("failed to render template")
}

pub fn g2field_to_bn<F: FieldExt>(f: &F) -> (BigUint, BigUint) {
    (
        BigUint::from_bytes_le(&f.to_repr().as_ref()[32..64]),
        BigUint::from_bytes_le(&f.to_repr().as_ref()[..32]),
    )
}

pub(crate) fn get_xy_from_g2point<E: MultiMillerLoop>(point: E::G2Affine) -> G2Point {
    let coordinates = point.coordinates();
    let x = coordinates
        .map(|v| *v.x())
        .unwrap_or(<E::G2Affine as CurveAffine>::Base::zero());
    let y = coordinates
        .map(|v| *v.y())
        .unwrap_or(<E::G2Affine as CurveAffine>::Base::zero());
    // let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());
    let x = g2field_to_bn(&x);
    let y = g2field_to_bn(&y);
    G2Point { x, y }
}

pub struct SolidityGenerate<E: Engine> {
    pub target_circuit_params: ParamsKZG<E>,
    pub target_circuit_vk: VerifyingKey<E::G1Affine>,
    pub nproofs: usize,
}

impl SolidityGenerate<Bn256> {
    pub fn new<SingleCircuit: TargetCircuit<Bn256>>(folder: &PathBuf) -> SolidityGenerate<Bn256> {
        let target_circuit_params =
            load_target_circuit_params::<Bn256, SingleCircuit>(&mut folder.clone());
        let target_circuit_vk = load_target_circuit_vk::<Bn256, SingleCircuit>(
            &mut folder.clone(),
            &target_circuit_params,
        );

        SolidityGenerate {
            target_circuit_params,
            target_circuit_vk,
            nproofs: SingleCircuit::N_PROOFS,
        }
    }
}

pub struct MultiCircuitSolidityGenerate<'a, E: MultiMillerLoop> {
    //pub target_circuits_params: [SolidityGenerate<E>; N],
    pub verify_params: &'a ParamsKZG<E>,
    pub verify_vk: &'a VerifyingKey<E::G1Affine>,
    // serialized instance
    pub verify_circuit_instance: Vec<Vec<Vec<E::Scalar>>>,
    // serialized proof
    pub proof: Vec<u8>,
    pub verify_public_inputs_size: usize,
}

impl<'a, E: MultiMillerLoop + Debug> MultiCircuitSolidityGenerate<'a, E> {
    pub fn call(&self, template_folder: std::path::PathBuf) -> String {
        let target_circuit_s_g2 = get_xy_from_g2point::<E>(self.verify_params.s_g2());
        let target_circuit_n_g2 = get_xy_from_g2point::<E>(-self.verify_params.g2());

        let verify_params = self.verify_params;

        let nchip = &SolidityFieldChip::new();
        let schip = nchip;
        let pchip = &SolidityEccChip::new();
        let ctx = &mut SolidityCodeGeneratorContext::new();

        let mut transcript = CodegenTranscriptRead::<
            _,
            E::G1Affine,
            _,
            PoseidonEncode<_>,
            9usize,
            8usize,
        >::new(&self.proof[..], ctx, schip, 8usize, 63usize)
        .unwrap();

        let verify_circuit_instance1: Vec<Vec<&[E::Scalar]>> = self
            .verify_circuit_instance
            .iter()
            .map(|x| x.iter().map(|y| &y[..]).collect())
            .collect();
        let verify_circuit_instance2: Vec<&[&[E::Scalar]]> =
            verify_circuit_instance1.iter().map(|x| &x[..]).collect();

        ctx.enter_instance();
        let (_, assigned_instances) = assign_instance_commitment(
            ctx,
            schip,
            pchip,
            &verify_circuit_instance2[..],
            self.verify_vk,
            verify_params,
        )
        .unwrap();
        ctx.exit_instance();

        let (proof, _) = verify_single_proof_no_eval(
            ctx,
            nchip,
            schip,
            pchip,
            assigned_instances,
            self.verify_vk,
            verify_params,
            &mut transcript,
            "".to_owned(),
        )
        .unwrap();

        let one = schip.assign_one(ctx).unwrap();

        let (left_s, left_e, _) = proof.w_x.eval::<_, _>(ctx, schip, pchip, &one).unwrap();
        let (right_s, right_e, _) = proof.w_g.eval::<_, _>(ctx, schip, pchip, &one).unwrap();

        let generator = pchip.assign_one(ctx).unwrap();
        let left = match left_e {
            None => left_s,
            Some(eval) => {
                let s = pchip.scalar_mul(ctx, &eval, &generator).unwrap();
                pchip.add(ctx, &left_s, &s).unwrap()
            }
        };
        let right = match right_e {
            None => right_s,
            Some(eval) => {
                let s = pchip.scalar_mul(ctx, &eval, &generator).unwrap();
                pchip.sub(ctx, &right_s, &s).unwrap()
            }
        };

        let verify_circuit_s_g2 = get_xy_from_g2point::<E>(self.verify_params.s_g2());
        let verify_circuit_n_g2 = get_xy_from_g2point::<E>(-self.verify_params.g2());

        let left_v = left.v.to_affine();
        let right_v = right.v.to_affine();
        let s_g2_prepared = E::G2Prepared::from(self.verify_params.s_g2());
        let n_g2_prepared = E::G2Prepared::from(-self.verify_params.g2());
        let (term_1, term_2) = ((&left_v, &s_g2_prepared), (&right_v, &n_g2_prepared));
        let terms = &[term_1, term_2];
        let success = bool::from(
            E::multi_miller_loop(terms)
                .final_exponentiation()
                .is_identity(),
        );
        log::debug!(
            "check pairing in solidity generation: {:?}({})",
            (
                left_v,
                right_v,
                self.verify_params.s_g2(),
                -self.verify_params.g2()
            ),
            success
        );
        //assert!(success);

        let sol_ctx = CodeGeneratorCtx {
            wx: (*left.expr).clone(),
            wg: (*right.expr).clone(),
            target_circuit_s_g2,
            target_circuit_n_g2,
            verify_circuit_s_g2,
            verify_circuit_n_g2,
            assignments: ctx.statements.clone(),
            memory_size: ctx.memory_offset,
            instance_size: ctx.instance_offset,
            absorbing_length: if ctx.absorbing_offset > ctx.max_absorbing_offset {
                ctx.absorbing_offset
            } else {
                ctx.max_absorbing_offset
            },
        };

        let sol_ctx: CodeGeneratorCtx = memory_optimize(sol_ctx);
        let sol_ctx: CodeGeneratorCtx = aggregate(sol_ctx);

        let template = render_verifier_sol_template::<E::G1Affine>(sol_ctx, template_folder);
        info!("generate solidity succeeds");

        template
    }
}
