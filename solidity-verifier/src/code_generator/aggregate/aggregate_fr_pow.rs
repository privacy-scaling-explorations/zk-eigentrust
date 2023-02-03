use super::{Action, GroupOptimizer};
use crate::code_generator::ctx::{Expression, Statement, Type};
use num_bigint::BigUint;
use std::rc::Rc;

pub(crate) struct AggregateFrPowOptimizer {
    unresolved_statements: Vec<Statement>,
    target: Option<Rc<Expression>>,
    assignee: Option<Rc<Expression>>,
    exp: usize,
    samples: Vec<BigUint>,
}

impl Default for AggregateFrPowOptimizer {
    fn default() -> Self {
        Self {
            assignee: None,
            target: None,
            exp: 0,
            unresolved_statements: vec![],
            samples: vec![],
        }
    }
}

impl AggregateFrPowOptimizer {
    fn is_complete(&self) -> bool {
        self.assignee.is_some()
    }
}

fn extract_mul(
    statement: &Statement,
) -> Option<(Rc<Expression>, Rc<Expression>, Rc<Expression>, Vec<BigUint>)> {
    match statement {
        Statement::Assign(l, r, samples) => match r {
            crate::code_generator::ctx::Expression::Mul(a, b, Type::Scalar) => {
                Some((l.clone(), a.clone(), b.clone(), samples.clone()))
            }
            _ => None,
        },
        _ => None,
    }
}

impl GroupOptimizer for AggregateFrPowOptimizer {
    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((l, a, b, samples)) = extract_mul(statement) {
            if l.is_temp() && a == b {
                self.target = Some(a);
                self.samples = samples;
                self.exp = 2;
                self.unresolved_statements.push(statement.clone());
                Action::Continue
            } else {
                Action::Skip
            }
        } else {
            Action::Skip
        }
    }

    fn try_merge(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if self.is_complete() {
            return Action::Complete;
        }

        if let Some((l, a, b, samples)) = extract_mul(statement) {
            if a.is_temp() && b.is_temp() {
                self.exp *= 2;
                self.samples = samples;
                if !l.is_temp() {
                    self.assignee = Some(l);
                }
                Action::Continue
            } else if (a.is_temp() && &b == self.target.as_ref().unwrap())
                || (b.is_temp() && &a == self.target.as_ref().unwrap())
            {
                self.exp += 1;
                self.samples = samples;
                if !l.is_temp() {
                    self.assignee = Some(l);
                }
                Action::Continue
            } else {
                Action::Abort
            }
        } else if self.exp > 2 {
            Action::Complete
        } else {
            Action::Abort
        }
    }

    fn to_statement(&self) -> crate::code_generator::ctx::Statement {
        Statement::Assign(
            self.assignee
                .clone()
                .unwrap_or(Rc::new(Expression::Temp(Type::Scalar))),
            Expression::Pow(self.target.clone().unwrap(), self.exp, Type::Scalar),
            self.samples.clone(),
        )
    }

    fn unresolved_statements(&self) -> Vec<Statement> {
        self.unresolved_statements.clone()
    }

    fn reset(&mut self) {
        self.assignee = None;
        self.target = None;
        self.exp = 0;
        self.unresolved_statements = vec![];
        self.samples = vec![];
    }

    fn can_complete(&self) -> bool {
        self.exp > 2
    }
}
