use super::{Action, GroupOptimizer};
use crate::code_generator::ctx::{Expression, Statement, Type};
use num_bigint::BigUint;
use std::rc::Rc;

const CAPABILITY: usize = 32;

pub(crate) struct MulAddMTOptimizer {
    unresolved_statements: Vec<Statement>,
    target: Option<usize>,
    byte_pairs: Vec<usize>,
    capability: usize,
    t: Type,
    samples: Vec<BigUint>,
}

impl Default for MulAddMTOptimizer {
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

impl MulAddMTOptimizer {
    fn is_complete(&self) -> bool {
        self.byte_pairs.len() == self.capability
    }
}

fn extract_mul_add(statement: &Statement) -> Option<(usize, usize, Vec<BigUint>)> {
    match statement {
        Statement::Assign(l, r, samples) => match r {
            crate::code_generator::ctx::Expression::MulAdd(a, b, c, Type::Scalar) => {
                if a.is_memory() && b.is_temp() && c.is_memory() && l.is_temp() {
                    Some((
                        a.try_get_offset().unwrap(),
                        c.try_get_offset().unwrap(),
                        samples.clone(),
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

impl GroupOptimizer for MulAddMTOptimizer {
    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((a_offset, c_offset, samples)) = extract_mul_add(statement) {
            self.byte_pairs.push(c_offset);
            self.target = Some(a_offset);
            self.samples = samples;
            self.unresolved_statements.push(statement.clone());
            Action::Continue
        } else {
            Action::Skip
        }
    }

    fn try_merge(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if self.is_complete() {
            return Action::Complete;
        }

        if let Some((a_offset, c_offset, samples)) = extract_mul_add(statement) {
            if a_offset == *self.target.as_ref().unwrap() {
                self.byte_pairs.push(c_offset);
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
            BigUint::from(0xffu64)
        };
        let opcode = self
            .byte_pairs
            .iter()
            .rev()
            .fold(init, |acc, m| (acc << 8u8) + (m));
        Statement::Assign(
            Rc::new(Expression::Temp(self.t.clone())),
            Expression::MulAddMT(self.target.unwrap(), opcode),
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
