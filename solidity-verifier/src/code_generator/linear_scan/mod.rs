pub(crate) mod live_interval;
pub(crate) mod memory_pool;
pub(crate) mod optimize;

use self::{
    live_interval::{build_intervals, Interval},
    memory_pool::{MemoryBlock, MemoryPool},
    optimize::optimize,
};
use super::ctx::{CodeGeneratorCtx, Expression, Statement, Type};
use std::collections::{HashMap, HashSet};

fn linear_scan(
    intervals: &mut Vec<Interval>,
    statements: &mut Vec<Statement>,
    expressions: &mut Vec<Expression>,
    pool: &mut MemoryPool,
) -> usize {
    let active = &mut HashSet::<Interval>::new();

    intervals.iter_mut().for_each(|i| {
        expire_old_intervals(active, i, pool);

        let mem_block = if i.end == i.start + 1 {
            MemoryBlock {
                pos: 0xdeadbeaf,
                t: Type::Scalar,
            }
        } else {
            match i.t {
                Type::Scalar => {
                    if pool.free_256_block.is_empty() {
                        pool.expand();
                    }
                    pool.alloc_scalar()
                }
                Type::Point => {
                    if pool.free_512_block.is_empty() {
                        pool.expand();
                    }
                    pool.alloc_point()
                }
            }
        };

        let mut replaced_expr = HashMap::<usize, usize>::new();
        replaced_expr.insert(i.expr, mem_block.pos);

        for statement in &mut statements[i.start..] {
            *statement = statement.substitute(&replaced_expr);
        }
        for expression in expressions.as_mut_slice() {
            *expression = expression.substitute(&replaced_expr);
        }

        if mem_block.pos != 0xdeadbeaf {
            i.mem_block = Some(mem_block);
            active.insert(i.clone());
        }
    });

    pool.capability
}

fn expire_old_intervals(active: &mut HashSet<Interval>, i: &Interval, pool: &mut MemoryPool) {
    let active_vec = &mut active.clone().into_iter().collect::<Vec<_>>();

    active_vec.iter().for_each(|j| {
        if j.end <= i.start {
            pool.free(j.mem_block.clone().unwrap());
            active.remove(j);
        }
    })
}

pub(crate) fn memory_optimize(mut ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let mut expressions = vec![ctx.wx, ctx.wg];
    let (intervals, lookup) = &mut build_intervals(&mut ctx.assignments, &expressions);
    let mut assignments = optimize(ctx.assignments, intervals, lookup);

    let (intervals, _) = &mut build_intervals(&mut assignments, &expressions);
    let empty_pool = &mut MemoryPool::default();
    let memory_offset = linear_scan(intervals, &mut assignments, &mut expressions, empty_pool);

    ctx.wx = expressions[0].clone();
    ctx.wg = expressions[1].clone();
    ctx.assignments = assignments;
    ctx.memory_size = memory_offset;

    ctx
}
