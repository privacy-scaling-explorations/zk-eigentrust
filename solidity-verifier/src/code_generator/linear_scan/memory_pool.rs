use std::collections::BTreeSet;

use crate::code_generator::ctx::Type;

#[derive(Hash, PartialEq, Eq, Clone)]
pub(crate) struct MemoryBlock {
    pub(crate) pos: usize,
    pub(crate) t: Type,
}

pub(crate) struct MemoryPool {
    // 0, 1, 2, ...
    pub(crate) free_256_block: BTreeSet<usize>,
    // 0, 2, 4, ...
    pub(crate) free_512_block: BTreeSet<usize>,
    pub(crate) capability: usize,
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self {
            free_256_block: BTreeSet::<usize>::new(),
            free_512_block: BTreeSet::<usize>::new(),
            capability: 0,
        }
    }
}

impl MemoryPool {
    pub(crate) fn alloc_scalar(&mut self) -> MemoryBlock {
        let pos = *self.free_256_block.iter().next().unwrap();
        self.free_256_block.remove(&pos);
        self.free_512_block.remove(&(pos - (pos % 2)));

        MemoryBlock {
            pos,
            t: Type::Scalar,
        }
    }

    pub(crate) fn alloc_point(&mut self) -> MemoryBlock {
        let pos = *self.free_512_block.iter().next().unwrap();
        self.free_256_block.remove(&pos);
        self.free_256_block.remove(&(pos + 1));
        self.free_512_block.remove(&pos);

        MemoryBlock {
            pos,
            t: Type::Point,
        }
    }

    pub(crate) fn free(&mut self, block: MemoryBlock) {
        match block.t {
            Type::Scalar => {
                self.free_256_block.insert(block.pos);

                let base = block.pos - (block.pos % 2);
                if self.free_256_block.contains(&base) && self.free_256_block.contains(&(base + 1))
                {
                    self.free_512_block.insert(base);
                }
            }
            Type::Point => {
                self.free_256_block.insert(block.pos);
                self.free_256_block.insert(block.pos + 1);
                self.free_512_block.insert(block.pos);
            }
        }
    }

    pub(crate) fn expand(&mut self) -> usize {
        let addr = self.capability;
        self.free_256_block.insert(addr);
        self.free_256_block.insert(addr + 1);
        self.free_512_block.insert(addr);
        self.capability += 2;
        addr
    }
}
