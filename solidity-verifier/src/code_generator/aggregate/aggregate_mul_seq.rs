use super::{Action, GroupOptimizer};
use crate::code_generator::ctx::{Statement, Type};
use num_bigint::BigUint;

pub(crate) struct AggregateMulSeqOptimizer {
    unresolved_statements: Vec<Statement>,
    l_step: Option<usize>,
    a_step: Option<usize>,
    b_step: Option<usize>,
    l_start: usize,
    a_start: usize,
    b_start: usize,
    capability: usize,
}

impl Default for AggregateMulSeqOptimizer {
    fn default() -> Self {
        Self {
            l_step: None,
            a_step: None,
            b_step: None,
            l_start: 0usize,
            a_start: 0usize,
            b_start: 0usize,
            capability: 0usize,
            unresolved_statements: vec![],
        }
    }
}

impl AggregateMulSeqOptimizer {
    fn is_complete(&self) -> bool {
        false
    }
}

fn extract_mul(statement: &Statement) -> Option<(usize, usize, usize, Vec<BigUint>)> {
    match statement {
        Statement::Assign(l, r, samples) => match r {
            crate::code_generator::ctx::Expression::Mul(a, b, Type::Scalar) => {
                if a.is_memory() && b.is_memory() && l.is_memory() {
                    Some((
                        l.try_get_offset().unwrap(),
                        a.try_get_offset().unwrap(),
                        b.try_get_offset().unwrap(),
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

impl GroupOptimizer for AggregateMulSeqOptimizer {
    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((l_offset, a_offset, b_offset, _)) = extract_mul(statement) {
            self.l_start = l_offset;
            self.a_start = a_offset;
            self.b_start = b_offset;
            self.capability = 1;
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

        if let Some((l_offset, a_offset, b_offset, _)) = extract_mul(statement) {
            if self.l_step.is_none() {
                self.l_step = Some(l_offset - self.l_start);
                self.a_step = Some(a_offset - self.a_start);
                self.b_step = Some(b_offset - self.b_start);
                self.capability += 1;
                self.unresolved_statements.push(statement.clone());
                return Action::Continue;
            } else if self.l_step.is_some()
                && l_offset - self.l_start == self.capability * self.l_step.unwrap()
                && a_offset - self.a_start == self.capability * self.a_step.unwrap()
                && b_offset - self.b_start == self.capability * self.b_step.unwrap()
            {
                self.capability += 1;
                self.unresolved_statements.push(statement.clone());
                return Action::Continue;
            }
        }

        if self.can_complete() {
            Action::Complete
        } else {
            Action::Abort
        }
    }

    fn to_statement(&self) -> crate::code_generator::ctx::Statement {
        Statement::ForMMMMul {
            start: (self.l_start, self.a_start, self.b_start),
            step: (
                self.l_step.unwrap(),
                self.a_step.unwrap(),
                self.b_step.unwrap(),
            ),
            n: self.capability,
            t: Type::Scalar,
        }
    }

    fn unresolved_statements(&self) -> Vec<Statement> {
        self.unresolved_statements.clone()
    }

    fn reset(&mut self) {
        self.l_step = None;
        self.a_step = None;
        self.b_step = None;
        self.l_start = 0usize;
        self.a_start = 0usize;
        self.b_start = 0usize;
        self.capability = 0usize;
        self.unresolved_statements = vec![];
    }

    fn can_complete(&self) -> bool {
        self.capability > 4
    }
}
