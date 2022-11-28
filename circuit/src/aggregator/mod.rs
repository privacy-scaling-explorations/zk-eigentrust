#![allow(missing_docs)]
mod accumulation;
mod common_poly;
mod msm;
mod protocol;
mod shplonk;
mod transcript;

const WIDTH: usize = 5;
const NUM_LIMBS: usize = 4;
const NUM_BITS: usize = 68;
