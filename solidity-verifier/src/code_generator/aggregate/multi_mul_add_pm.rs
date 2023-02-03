use super::{Action, GroupOptimizer};
use crate::code_generator::ctx::{Expression, Statement, Type};
use num_bigint::BigUint;
use std::rc::Rc;

const CAPABILITY: usize = 16;

pub(crate) struct MulAddPMOptimizer {
    unresolved_statements: Vec<Statement>,
    target: Option<Expression>,
    byte_pairs: Vec<(usize, usize)>,
    capability: usize,
    t: Type,
    samples: Vec<BigUint>,
}

impl Default for MulAddPMOptimizer {
    fn default() -> Self {
        Self {
            target: None,
            byte_pairs: Default::default(),
            capability: CAPABILITY,
            unresolved_statements: vec![],
            t: Type::Scalar,
            samples: vec![],
        }
    }
}

impl MulAddPMOptimizer {
    fn is_complete(&self) -> bool {
        self.byte_pairs.len() == self.capability
    }
}

fn extract_mul_add(
    statement: &Statement,
) -> Option<(usize, usize, Expression, Vec<BigUint>, Type)> {
    match statement {
        Statement::Assign(l, r, samples) => match r {
            crate::code_generator::ctx::Expression::MulAdd(a, b, c, t) => {
                if a.is_transcript() && b.is_memory() && c.is_temp() && l.is_temp() {
                    Some((
                        a.try_get_offset().unwrap(),
                        b.try_get_offset().unwrap(),
                        c.as_ref().clone(),
                        samples.clone(),
                        t.clone(),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

impl GroupOptimizer for MulAddPMOptimizer {
    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((proof_offset, memory_offset, target, samples, t)) = extract_mul_add(statement)
        {
            self.byte_pairs.push((proof_offset, memory_offset));
            self.target = Some(target);
            self.samples = samples;
            self.unresolved_statements.push(statement.clone());
            self.t = t;
            Action::Continue
        } else {
            Action::Skip
        }
    }

    fn try_merge(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if self.is_complete() {
            return Action::Complete;
        }

        if let Some((proof_offset, memory_offset, target, samples, t)) = extract_mul_add(statement)
        {
            if target == *self.target.as_ref().unwrap() && t == self.t {
                self.byte_pairs.push((proof_offset, memory_offset));
                self.samples = samples;
                self.unresolved_statements.push(statement.clone());
                Action::Continue
            } else {
                Action::Abort
            }
        } else if self.byte_pairs.len() > 1 {
            Action::Complete
        } else {
            Action::Abort
        }
    }

    fn to_statement(&self) -> crate::code_generator::ctx::Statement {
        let init = if self.byte_pairs.len() == CAPABILITY {
            BigUint::from(0u64)
        } else {
            BigUint::from(0xffffu64)
        };
        let opcode = self
            .byte_pairs
            .iter()
            .rev()
            .fold(init, |acc, (p, m)| (acc << 16u8) + (m << 8) + p);
        Statement::Assign(
            Rc::new(Expression::Temp(self.t.clone())),
            Expression::MulAddPM(
                Rc::new(self.target.clone().unwrap()),
                opcode,
                self.t.clone(),
            ),
            self.samples.clone(),
        )
    }

    fn unresolved_statements(&self) -> Vec<Statement> {
        self.unresolved_statements.clone()
    }

    fn reset(&mut self) {
        self.byte_pairs = vec![];
        self.target = None;
        self.unresolved_statements = vec![];
    }

    fn can_complete(&self) -> bool {
        self.byte_pairs.len() > 1
    }
}
