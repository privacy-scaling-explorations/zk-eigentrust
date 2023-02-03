use super::memory_pool::MemoryBlock;
use crate::code_generator::ctx::{Expression, Statement, Type};
use std::{collections::HashMap, rc::Rc};

#[derive(Hash, PartialEq, Eq, Clone)]
pub(crate) struct Interval {
    pub(crate) expr: usize,
    pub(crate) t: Type,
    pub(crate) mem_block: Option<MemoryBlock>,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) value: Expression,
}

pub(crate) fn build_intervals(
    statements: &Vec<Statement>,
    expressions: &Vec<Expression>,
) -> (Vec<Interval>, HashMap<Rc<Expression>, usize>) {
    let mut intervals: Vec<Interval> = vec![];
    // from memory offset to statement array offset
    let mut lookup = HashMap::<Rc<Expression>, usize>::new();

    statements
        .iter()
        .enumerate()
        .for_each(|(current, s)| match s {
            Statement::Assign(l, r, _) => {
                let offset = match **l {
                    Expression::Memory(o, _) => o,
                    _ => unreachable!(),
                };

                let interval = Interval {
                    start: current,
                    end: current,
                    expr: offset,
                    t: l.get_type(),
                    mem_block: None,
                    value: r.clone(),
                };

                lookup.insert(l.clone(), intervals.len());
                intervals.push(interval);

                r.iter(&mut |e| {
                    let expr = lookup.get(e);
                    if expr.is_some() {
                        intervals[*expr.unwrap()].end = current;
                    }
                });
            }
            Statement::UpdateHash(e, _) => {
                e.iter(&mut |e| {
                    let expr = lookup.get(e);
                    if expr.is_some() {
                        intervals[*expr.unwrap()].end = current;
                    }
                });
            }
            _ => unreachable!(),
        });

    expressions.iter().for_each(|expression| {
        expression.iter(&mut |e| {
            let expr = lookup.get(e);
            if expr.is_some() {
                intervals[*expr.unwrap()].end = statements.len() + 1;
            }
        })
    });

    (intervals, lookup)
}
