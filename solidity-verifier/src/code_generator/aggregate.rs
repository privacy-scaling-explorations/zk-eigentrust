use self::{
    aggregate_fr_pow::AggregateFrPowOptimizer, aggregate_mul_seq::AggregateMulSeqOptimizer,
    multi_mul_add_mt::MulAddMTOptimizer, update_hash::UpdateHashMerger,
};
use super::ctx::{CodeGeneratorCtx, Statement};
use crate::code_generator::aggregate::multi_mul_add_pm::MulAddPMOptimizer;
use std::any::Any;

mod aggregate_fr_pow;
mod aggregate_mul_seq;
mod multi_mul_add_mt;
mod multi_mul_add_pm;
mod update_hash;

#[derive(PartialEq)]
pub(crate) enum Status {
    Disabled,
    Active,
    Terminated,
}

#[derive(PartialEq)]
pub(crate) enum Action {
    // Failed to merge
    Skip,
    // Merged
    Continue,
    // Failed, should re-dump feeded statements
    Abort,
    // Success
    Complete,
}

trait GroupOptimizer: Any {
    fn try_start(&mut self, statement: &Statement) -> Action;
    fn try_merge(&mut self, statement: &Statement) -> Action;
    fn to_statement(&self) -> Statement;
    fn unresolved_statements(&self) -> Vec<Statement>;
    fn reset(&mut self);
    fn can_complete(&self) -> bool;
}

pub(crate) fn aggregate(mut ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let update_hash_merger = Box::new(UpdateHashMerger::default());
    let multi_muladd_pm_merger = Box::new(MulAddPMOptimizer::default());
    let multi_muladd_mt_merger = Box::new(MulAddMTOptimizer::default());
    let aggregate_fr_pow = Box::new(AggregateFrPowOptimizer::default());
    let aggregate_mul_seq = Box::new(AggregateMulSeqOptimizer::default()); //

    // Replace todo! with multi_muladd_pm_merger
    let mut optimizer: Vec<Box<dyn GroupOptimizer>> = vec![
        update_hash_merger,
        multi_muladd_pm_merger,
        multi_muladd_mt_merger,
        aggregate_fr_pow,
        aggregate_mul_seq,
    ];
    /*
     * Status of optimizer
     *
     *  +-------------------+
     *  |  Skip             |
     *  |                   v
     *  +-----------------  Disabled(try to start for each statement)  <-+
     *                                                                   |
     *                      |    Continue                                |
     *                                                                   |
     *  +---------------->  Active(opt_in_processing.is_some())          | Terminate(stage 2)
     *  | Continue                                                       |
     *  +-----------------  |    Terminate/Complete                      |
     *                                                                   |
     *                      Terminated ----------------------------------+
     *
     * Action for state transition
     *
     *   + Skip: (Disabled -> Disabled) failed to merge in, processing statement should be output
     *   + Continue: (Disabled/Active -> Active) merged, statement should be fed into optimizer
     *   + Complete: Successfully group a batch of instructions, HOWEVER the current instruction is not included, so you should
     *               not move iterator forward
     *   + Terminate: (Active -> Terminated -> Disabled) Unmergeable statement, optimizer should be flushed and try to enable a new optimizer
     */

    for optimizer in optimizer.iter_mut() {
        let mut it = ctx.assignments.iter();
        let mut statements = vec![];
        let mut status = Status::Disabled;

        let mut cursor: Option<_> = it.next();
        while let Some(statement) = cursor {
            match status {
                Status::Disabled => {
                    match optimizer.as_mut().try_start(statement) {
                        Action::Continue => {
                            status = Status::Active;
                        }
                        Action::Skip => {
                            statements.push(statement.clone());
                        }
                        _ => unreachable!(),
                    }
                    cursor = it.next();
                }
                Status::Active => match optimizer.as_mut().try_merge(statement) {
                    Action::Skip => unreachable!(),
                    Action::Continue => cursor = it.next(),
                    Action::Abort => {
                        statements.append(&mut optimizer.as_ref().unresolved_statements());
                        status = Status::Terminated;
                    }
                    Action::Complete => {
                        statements.push(optimizer.as_ref().to_statement());
                        status = Status::Terminated;
                    }
                },
                Status::Terminated => {
                    optimizer.as_mut().reset();
                    status = Status::Disabled;
                    continue;
                }
            }
        }

        if status != Status::Disabled {
            if optimizer.as_ref().can_complete() {
                statements.push(optimizer.as_ref().to_statement());
            } else {
                statements.append(&mut optimizer.as_ref().unresolved_statements());
            }
        }

        ctx.assignments = statements;
    }

    ctx
}
