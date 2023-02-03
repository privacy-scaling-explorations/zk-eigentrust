use super::live_interval::Interval;
use crate::code_generator::ctx::{Expression, Statement, Type};
use std::{collections::HashMap, rc::Rc};

pub(crate) fn optimize(
    statements: Vec<Statement>,
    intervals: &Vec<Interval>,
    lookup: &HashMap<Rc<Expression>, usize>,
) -> Vec<Statement> {
    combine_mul_add(statements, intervals, lookup)
}

fn combine_mul_add(
    statements: Vec<Statement>,
    intervals: &Vec<Interval>,
    lookup: &HashMap<Rc<Expression>, usize>,
) -> Vec<Statement> {
    let mut new_statements = vec![];
    let mut candidate_statement_opt: Option<Statement> = None;

    for (i, statement) in statements.into_iter().enumerate() {
        let able_to_be_optimized = statement.able_to_be_optimized(i, intervals, lookup);

        match candidate_statement_opt {
            None => {
                if able_to_be_optimized {
                    candidate_statement_opt = Some(statement);
                } else {
                    new_statements.push(statement);
                }
            }
            Some(candidate_statement) => {
                let mul_add = candidate_statement.combine_mul_add(&statement);
                match mul_add {
                    Some(statement) => {
                        new_statements.push(statement);
                        candidate_statement_opt = None;
                    }
                    _ => {
                        new_statements.push(candidate_statement);
                        if able_to_be_optimized {
                            candidate_statement_opt = Some(statement);
                        } else {
                            new_statements.push(statement);
                            candidate_statement_opt = None;
                        }
                    }
                }
            }
        }
    }

    if candidate_statement_opt.is_some() {
        new_statements.push(candidate_statement_opt.unwrap());
    }

    new_statements
}

impl Statement {
    pub fn able_to_be_optimized(
        &self,
        index: usize,
        intervals: &Vec<Interval>,
        lookup: &HashMap<Rc<Expression>, usize>,
    ) -> bool {
        if let Some(assignee) = self.get_assignee() {
            // Only optimize intermediate value
            intervals[*lookup.get(&assignee).unwrap()].end == index + 1
        } else {
            false
        }
    }

    pub fn get_assignee(&self) -> Option<Rc<Expression>> {
        match self {
            Statement::Assign(assignee, _, _) => Some(assignee.clone()),
            _ => None,
        }
    }

    pub fn combine_mul_add(&self, next: &Statement) -> Option<Statement> {
        let curr = match self {
            Statement::Assign(assignee, Expression::Mul(l, r, t), _) => {
                if true {
                    Some((assignee, l, r, t))
                } else if *t == Type::Point {
                    Some((assignee, l, r, t))
                } else {
                    None
                }
            }
            _ => None,
        };

        match curr {
            None => None,
            Some((assignee, l, r, t)) => match next {
                Statement::Assign(new_assignee, Expression::Add(new_l, new_r, new_t), samples) => {
                    if new_l == assignee && t == new_t {
                        Some(Statement::Assign(
                            new_assignee.clone(),
                            Expression::MulAdd(r.clone(), l.clone(), new_r.clone(), t.clone()),
                            samples.clone(),
                        ))
                    } else if new_r == assignee && t == new_t {
                        Some(Statement::Assign(
                            new_assignee.clone(),
                            Expression::MulAdd(r.clone(), l.clone(), new_l.clone(), t.clone()),
                            samples.clone(),
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
        }
    }
}
