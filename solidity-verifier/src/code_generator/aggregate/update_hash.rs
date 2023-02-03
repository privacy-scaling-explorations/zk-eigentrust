use std::{ops::Deref, rc::Rc};

use crate::code_generator::ctx::{Expression, Statement, Type};

use super::{Action, GroupOptimizer};

pub(crate) struct UpdateHashMerger {
    memory_offset_start: usize,
    memory_offset_end: usize,
    absorbing_start: usize,
    absorbing_end: usize,
    step_memory_offset: usize,
    step_absorbing_offset: usize,
    in_processing: bool,
    t: Type,
}

impl Default for UpdateHashMerger {
    fn default() -> Self {
        Self {
            memory_offset_start: Default::default(),
            memory_offset_end: Default::default(),
            absorbing_start: Default::default(),
            absorbing_end: Default::default(),
            step_memory_offset: Default::default(),
            step_absorbing_offset: Default::default(),
            in_processing: false,
            t: Type::Scalar,
        }
    }
}
impl GroupOptimizer for UpdateHashMerger {
    fn try_start(&mut self, statement: &Statement) -> Action {
        match statement {
            Statement::UpdateHash(e, absorbing_offset) => match e.deref() {
                Expression::TransciprtOffset(memory_offset, t) => {
                    self.memory_offset_start = *memory_offset;
                    self.memory_offset_end = *memory_offset;
                    self.absorbing_start = *absorbing_offset;
                    self.absorbing_end = *absorbing_offset;
                    self.step_memory_offset = if *t == Type::Scalar { 1 } else { 2 };
                    self.step_absorbing_offset = if *t == Type::Scalar { 2 } else { 3 };
                    self.in_processing = true;
                    self.t = t.clone();
                    Action::Continue
                }
                _ => Action::Skip,
            },
            _ => Action::Skip,
        }
    }

    fn try_merge(&mut self, statement: &Statement) -> Action {
        if let Statement::UpdateHash(e, absorbing_offset) = statement {
            if let Expression::TransciprtOffset(memory_offset, ty) = &*(e.clone()) {
                if memory_offset - self.memory_offset_end == self.step_memory_offset
                    && absorbing_offset - self.absorbing_end == self.step_absorbing_offset
                    && *ty == self.t
                {
                    self.memory_offset_end = *memory_offset;
                    self.absorbing_end = *absorbing_offset;
                    Action::Continue
                } else {
                    Action::Complete
                }
            } else {
                Action::Complete
            }
        } else {
            Action::Complete
        }
    }

    fn to_statement(&self) -> Statement {
        if self.memory_offset_start == self.memory_offset_end {
            Statement::UpdateHash(
                Rc::new(Expression::TransciprtOffset(
                    self.memory_offset_start,
                    Type::Scalar,
                )),
                self.absorbing_start,
            )
        } else {
            Statement::For {
                memory_start: self.memory_offset_start,
                memory_end: self.memory_offset_end,
                memory_step: self.step_memory_offset,
                absorbing_start: self.absorbing_start,
                absorbing_step: self.step_absorbing_offset,
                t: self.t.clone(),
            }
        }
    }

    fn unresolved_statements(&self) -> Vec<Statement> {
        // Since the optimizer doesn't return Action::Terminate
        unreachable!()
    }

    fn reset(&mut self) {
        self.in_processing = false;
    }

    fn can_complete(&self) -> bool {
        self.in_processing
    }
}
