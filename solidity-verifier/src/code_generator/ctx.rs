use num_bigint::BigUint;
use std::{collections::HashMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Scalar,
    Point,
}

impl Type {
    fn to_length(&self) -> usize {
        match &self {
            Type::Scalar => 1,
            Type::Point => 2,
        }
    }

    fn to_libstring(&self) -> String {
        match &self {
            Type::Scalar => "fr".to_owned(),
            Type::Point => "ecc".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expression {
    Memory(usize, Type),
    TransciprtOffset(usize, Type),
    InstanceOffset(usize, Type),
    // TODO: Remove
    TmpBufOffset(usize, Type),
    Point(BigUint, BigUint),
    Scalar(BigUint),
    Add(Rc<Expression>, Rc<Expression>, Type),
    Sub(Rc<Expression>, Rc<Expression>, Type),
    Mul(Rc<Expression>, Rc<Expression>, Type),
    Div(Rc<Expression>, Rc<Expression>, Type),
    MulAdd(Rc<Expression>, Rc<Expression>, Rc<Expression>, Type),
    MulAddPM(Rc<Expression>, BigUint, Type),
    MulAddMT(usize, BigUint),
    Pow(Rc<Expression>, usize, Type),
    Hash(usize),
    Temp(Type),
}

impl Expression {
    pub fn is_memory(&self) -> bool {
        match self {
            Expression::Memory(..) => true,
            _ => false,
        }
    }

    pub fn is_transcript(&self) -> bool {
        match self {
            Expression::TransciprtOffset(..) => true,
            _ => false,
        }
    }

    pub fn is_temp(&self) -> bool {
        match self {
            Expression::Temp(..) => true,
            _ => false,
        }
    }

    pub fn try_get_offset(&self) -> Option<usize> {
        match self {
            Expression::Memory(offset, ..) => Some(*offset),
            Expression::TransciprtOffset(offset, ..) => Some(*offset),
            Expression::InstanceOffset(offset, ..) => Some(*offset),
            Expression::TmpBufOffset(offset, ..) => Some(*offset),
            _ => None,
        }
    }

    pub(crate) fn get_type(&self) -> Type {
        match &self {
            Expression::Memory(_, t)
            | Expression::TransciprtOffset(_, t)
            | Expression::InstanceOffset(_, t)
            | Expression::TmpBufOffset(_, t)
            | Expression::Add(_, _, t)
            | Expression::Sub(_, _, t)
            | Expression::Mul(_, _, t)
            | Expression::Div(_, _, t)
            | Expression::MulAdd(_, _, _, t) => (*t).clone(),
            Expression::Point(_, _) => Type::Point,
            Expression::Scalar(_) => Type::Scalar,
            Expression::Hash(_) => Type::Scalar,
            Expression::Pow(_, _, t) => (*t).clone(),
            Expression::Temp(t) => (*t).clone(),
            Expression::MulAddPM(_, _, t) => (*t).clone(),
            Expression::MulAddMT(_, _) => Type::Scalar,
        }
    }

    pub fn to_untyped_string(&self) -> String {
        match self {
            Expression::Memory(idx, Type::Scalar) => format!("m[{}]", idx),
            Expression::Memory(idx, Type::Point) => format!("(m[{}], m[{}])", idx, idx + 1),
            Expression::Temp(Type::Scalar) => "t0".to_string(),
            Expression::Temp(Type::Point) => "(t0, t1)".to_string(),
            _ => unreachable!(),
        }
    }

    pub fn to_mem_string(&self, offset: usize) -> String {
        match self {
            Expression::Memory(idx, Type::Scalar) => format!("m[{}]", idx),
            Expression::Memory(idx, Type::Point) => format!("m[{}]", idx + offset),
            _ => unreachable!(),
        }
    }

    pub fn to_mem_code(&self) -> Option<u64> {
        None
        /*
        const MEM_SEP: u64 = 3u64 << 7;
        const CONST_SEP: u64 = 2u64 << 7;
        const CONST_LIMIT: u64 = 128u64;
        match self {
            Expression::Memory(idx, _) => {
                //assert!(*idx <= 127);
                Some(MEM_SEP + *idx as u64)
            }
            Expression::TransciprtOffset(offset, _) => {
                assert!(*offset <= 255);
                Some(*offset as u64)
            }
            Expression::Scalar(s) => {
                if s == &BigUint::from(0u64) {
                    Some(CONST_SEP)
                } else if s < &BigUint::from(CONST_LIMIT) {
                    Some(CONST_SEP + s.to_u64_digits()[0])
                } else {
                    None
                }
            }
            _ => None,
        }
        */
    }

    pub fn to_short_code(&self) -> Option<u64> {
        const OP_SHIFT: usize = 18usize;
        const R0_SHIFT: usize = 9usize;
        match self {
            Expression::Add(l, r, Type::Scalar) => l.to_mem_code().and_then(|idx0| {
                r.to_mem_code()
                    .map(|idx1| (1u64 << OP_SHIFT) + (idx0 << R0_SHIFT) + idx1)
            }),
            Expression::Sub(l, r, Type::Scalar) => l.to_mem_code().and_then(|idx0| {
                r.to_mem_code()
                    .map(|idx1| (2u64 << OP_SHIFT) + (idx0 << R0_SHIFT) + idx1)
            }),
            Expression::Mul(l, r, Type::Scalar) => l.to_mem_code().and_then(|idx0| {
                r.to_mem_code()
                    .map(|idx1| (3u64 << OP_SHIFT) + (idx1 << R0_SHIFT) + idx0)
            }),
            _ => None,
        }
    }

    pub fn to_typed_string(&self) -> String {
        match self {
            Expression::Scalar(s) => format!("{}", s),
            Expression::Point(x, y) => {
                format!("{}, {}", x, y)
            }
            Expression::Memory(idx, Type::Scalar) => format!("m[{}]", idx),
            Expression::Memory(idx, Type::Point) => {
                format!("m[{}], m[{}]", idx, idx + 1)
            }
            Expression::Add(l, r, Type::Point) => format!(
                "ecc_add({}, {})",
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Add(l, r, Type::Scalar) => format!(
                "addmod({}, {}, q_mod)",
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Sub(l, r, Type::Point) => format!(
                "ecc_sub({}, {})",
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Sub(l, r, Type::Scalar) => format!(
                "addmod({}, q_mod - {}, q_mod)",
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Mul(s, p, Type::Point) => format!(
                "ecc_mul({}, {})",
                (*p).to_typed_string(),
                (*s).to_typed_string()
            ),
            Expression::Mul(l, r, Type::Scalar) => format!(
                "mulmod({}, {}, q_mod)",
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Div(l, r, t) => format!(
                "{}_div({}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::MulAdd(l, r, c, t) => format!(
                "{}_mul_add({}, {}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string(),
                (*c).to_typed_string()
            ),
            Expression::TransciprtOffset(offset, t) => match t {
                Type::Scalar => format!("proof[{}]", offset),
                Type::Point => format!("proof[{}], proof[{}]", offset, offset + 1),
            },
            Expression::InstanceOffset(offset, t) => match t {
                Type::Scalar => format!("instances[{}]", offset),
                Type::Point => {
                    format!("instances[{}], instances[{}]", offset, offset + 1)
                }
            },
            Expression::TmpBufOffset(offset, t) => {
                format!("{}_from_bytes(vars, {})", t.to_libstring(), offset)
            }
            Expression::Hash(offset) => {
                format!("squeeze_challenge(absorbing, {})", offset)
            }
            Expression::Pow(base, exp, t) => {
                assert_eq!(*t, Type::Scalar);
                format!("fr_pow({}, {})", (*base).to_typed_string(), exp)
            }
            Expression::Temp(Type::Scalar) => "t0".to_owned(),
            Expression::Temp(Type::Point) => "t0, t1".to_owned(),
            Expression::MulAddPM(target, opcode, t) => {
                format!(
                    "{}_mul_add_pm(m, proof, {}, {})",
                    t.to_libstring(),
                    opcode,
                    target.to_typed_string()
                )
            }
            Expression::MulAddMT(m, opcode) => {
                format!("fr_mul_add_mt(m, m[{}], {}, t0)", m, opcode)
            }
        }
    }

    pub(crate) fn iter(&self, f: &mut impl FnMut(&Expression)) {
        match self {
            Expression::Add(l, r, _)
            | Expression::Sub(l, r, _)
            | Expression::Mul(l, r, _)
            | Expression::Div(l, r, _) => {
                l.iter(f);
                r.iter(f);
            }
            Expression::MulAdd(l, r, c, _) => {
                l.iter(f);
                r.iter(f);
                c.iter(f);
            }
            Expression::Pow(base, _, _) => {
                base.iter(f);
            }
            t => f(t),
        }
    }

    pub(crate) fn map(&self, f: &impl Fn(&Expression) -> Expression) -> Expression {
        match self {
            Expression::Add(l, r, t) => {
                Expression::Add(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Sub(l, r, t) => {
                Expression::Sub(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Mul(l, r, t) => {
                Expression::Mul(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Div(l, r, t) => {
                Expression::Div(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::MulAdd(l, r, c, t) => Expression::MulAdd(
                Rc::new(l.map(f)),
                Rc::new(r.map(f)),
                Rc::new(c.map(f)),
                t.clone(),
            ),
            Expression::Pow(base, exp, t) => Expression::Pow(Rc::new(base.map(f)), *exp, t.clone()),
            t => f(t),
        }
    }

    pub(crate) fn substitute(&self, lookup: &HashMap<usize, usize>) -> Expression {
        let replace = |expr: &Expression| match expr {
            Expression::Memory(o, t) => match lookup.get(o) {
                Some(v) => {
                    if *v == 0xdeadbeaf {
                        Expression::Temp(t.clone())
                    } else {
                        Expression::Memory(*v, t.clone())
                    }
                }
                None => expr.clone(),
            },
            _ => expr.clone(),
        };

        self.map(&replace)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Statement {
    Assign(Rc<Expression>, Expression, Vec<BigUint>),
    UpdateHash(Rc<Expression>, usize),
    For {
        memory_start: usize,
        memory_end: usize,
        memory_step: usize,
        absorbing_start: usize,
        absorbing_step: usize,
        t: Type,
    },
    ForMMMMul {
        start: (usize, usize, usize),
        step: (usize, usize, usize),
        n: usize,
        t: Type,
    },
}

impl Statement {
    pub fn opcodes_to_solidity_string(opcodes: &mut Vec<u64>) -> Vec<String> {
        const OP_SIZE: usize = 32usize;
        const CHUNK_SIZE: usize = 256usize;

        if !opcodes.is_empty() {
            let chunks = opcodes.chunks(CHUNK_SIZE / OP_SIZE);
            let mut buf = vec![];
            for ops in chunks {
                let mut bn = BigUint::from(0u64);
                for op in ops {
                    //assert!(op < &(1u64 << OP_SIZE));
                    bn <<= OP_SIZE;
                    bn = bn + op
                }
                buf.push(format!("update(m, proof, absorbing, uint256({}));", bn));
            }
            buf
        } else {
            vec![]
        }
    }

    fn to_expect_string(&self, incremental_ident: &u64) -> Vec<String> {
        match self {
            Statement::Assign(l, r, samples) => match r.get_type() {
                Type::Point => vec![
                    format!(
                        "// require({} == {:?}, \"{}\");",
                        (*l).to_mem_string(0),
                        samples[0],
                        (*incremental_ident),
                    ),
                    format!(
                        "// require({} == {:?}, \"{}\");",
                        (*l).to_mem_string(1),
                        samples[1],
                        (*incremental_ident),
                    ),
                ],

                Type::Scalar => vec![format!(
                    "// require({} == {:?}, \"{}\");",
                    (*l).to_mem_string(0),
                    samples[0],
                    (*incremental_ident),
                )],
            },

            _ => vec![],
        }
    }

    fn to_origin_string(&self) -> Vec<String> {
        match self {
            Statement::Assign(l, r, _) => {
                if let Expression::Hash(_) = r {
                    vec![format!(
                        "{} = ({});",
                        (*l).to_untyped_string(),
                        (*r).to_typed_string(),
                    )]
                } else {
                    vec![format!(
                        "//{} = ({});",
                        (*l).to_untyped_string(),
                        (*r).to_typed_string(),
                    )]
                }
            }

            Statement::UpdateHash(_, _) => vec![],

            Statement::For {
                memory_start,
                memory_end,
                memory_step,
                absorbing_start,
                absorbing_step,
                t,
            } => {
                let mut output = vec![];

                output.push(format!(
                    "for (t0 = 0; t0 <= {}; t0++) {{",
                    (memory_end - memory_start) / memory_step,
                ));
                match *t {
                    Type::Scalar => {
                        output.push(format!(
                            "    update_hash_scalar(proof[{} + t0 * {}], absorbing, {} + t0 * {});",
                            memory_start, memory_step, absorbing_start, absorbing_step
                        ));
                    }
                    Type::Point => {
                        output.push(format!(
                            "    update_hash_point(proof[{} + t0 * {}], proof[{} + t0 * {}], absorbing, {} + t0 * {});",
                            memory_start, memory_step, memory_start + 1, memory_step,absorbing_start, absorbing_step
                        ));
                    }
                }

                output.push("}".to_string());

                output
            }
            Statement::ForMMMMul { start, step, n, t } => {
                let mut output = vec![];

                output.push(format!("for (t0 = 0; t0 < {}; t0++) {{", n,));
                match *t {
                    Type::Scalar => {
                        output.push(format!(
                            "    m[{} + t0 * {}] = (mulmod(m[{} + t0 * {}], m[{} + t0 * {}], q_mod));",
                            start.0, step.0, start.1, step.1, start.2, step.2,
                        ));
                    }
                    Type::Point => unreachable!(),
                }

                output.push("}".to_string());

                output
            }
        }
    }

    pub fn to_solidity_string(
        &self,
        opcodes: &mut Vec<u64>,
        incremental_ident: &mut u64,
    ) -> Vec<String> {
        const OPCODE_POINT_BITS: u64 = 1;
        const OPCODE_SCALAR_BITS: u64 = 0;

        const SHOW_ORIGIN: bool = true;
        const SHOW_EXPECT: bool = false;
        const SLOT_SIZE: u64 = 10;

        let mut ret = vec![];

        let opcode = match self {
            Statement::Assign(l, r, _) => match (l.to_mem_code(), r.to_short_code()) {
                (Some(l_code), Some(r_code)) => {
                    if SHOW_ORIGIN {
                        ret.append(&mut self.to_origin_string());
                    }
                    if SHOW_EXPECT {
                        ret.append(&mut self.to_expect_string(incremental_ident));
                    }

                    match r.get_type() {
                        Type::Point => Some((OPCODE_POINT_BITS << 31) + (l_code << 22) + r_code),
                        Type::Scalar => Some((OPCODE_SCALAR_BITS << 31) + (l_code << 22) + r_code),
                    }
                }
                _ => {
                    ret.append(&mut Self::opcodes_to_solidity_string(opcodes));
                    opcodes.clear();
                    ret.push(format!(
                        "{} = ({});",
                        (*l).to_untyped_string(),
                        (*r).to_typed_string()
                    ));
                    None
                }
            },

            Statement::UpdateHash(e, offset) => match e.get_type() {
                Type::Point => {
                    ret.append(&mut Self::opcodes_to_solidity_string(opcodes));
                    opcodes.clear();
                    ret.push(format!(
                        "update_hash_point({}, absorbing, {});",
                        e.to_typed_string(),
                        offset
                    ));
                    None
                }
                Type::Scalar => {
                    ret.append(&mut Self::opcodes_to_solidity_string(opcodes));
                    opcodes.clear();
                    ret.push(format!(
                        "update_hash_scalar({}, absorbing, {});",
                        e.to_typed_string(),
                        offset
                    ));
                    None
                }
            },

            _ => {
                ret.append(&mut self.to_origin_string());
                None
            }
        };

        if let Some(opcode) = opcode {
            opcodes.push(opcode);
        }

        if opcodes.len() >= 8 {
            ret.append(&mut Self::opcodes_to_solidity_string(opcodes));
            opcodes.clear();
        }

        *incremental_ident += SLOT_SIZE;

        ret
    }

    pub fn substitute(&self, lookup: &HashMap<usize, usize>) -> Statement {
        match self {
            Statement::Assign(l, r, s) => Statement::Assign(
                Rc::new(l.substitute(lookup)),
                r.substitute(lookup),
                s.clone(),
            ),
            Statement::UpdateHash(e, offset) => {
                Statement::UpdateHash(Rc::new(e.substitute(lookup)), *offset)
            }
            Statement::For { .. } => self.clone(),
            Statement::ForMMMMul { .. } => unreachable!(),
        }
    }
}

struct Cache {
    cache_assign: HashMap<Expression, Rc<Expression>>,
}

pub struct SolidityCodeGeneratorContext {
    pub(crate) absorbing_offset: usize,
    pub(crate) max_absorbing_offset: usize,
    pub(crate) memory_offset: usize,
    transcript_offset: usize,
    pub(crate) instance_offset: usize,
    tmp_offset: usize,
    pub(crate) var_buf: Vec<u8>,
    pub(crate) statements: Vec<Statement>,
    cache: Cache,
    mock_hash: bool,
    pub(crate) transcript_context: bool,
    pub(crate) instance_context: bool,
}

impl SolidityCodeGeneratorContext {
    pub(crate) fn enter_hash(&mut self) {
        self.mock_hash = true;
    }

    pub(crate) fn enter_transcript(&mut self) {
        self.transcript_context = true;
    }

    pub(crate) fn exit_transcript(&mut self) {
        self.transcript_context = false;
    }

    pub(crate) fn enter_instance(&mut self) {
        self.instance_context = true;
    }

    pub(crate) fn exit_instance(&mut self) {
        self.instance_context = false;
    }

    pub(crate) fn squeeze_challenge_scalar(
        &mut self,
        offset: usize,
        sample: BigUint,
    ) -> Rc<Expression> {
        self.mock_hash = false;
        let l = self.allocate(Type::Scalar);
        let r = Expression::Hash(offset);
        self.statements
            .push(Statement::Assign(l.clone(), r, vec![sample]));

        l
    }

    pub(crate) fn update(&mut self, expr: &Rc<Expression>, offset: usize) {
        self.statements
            .push(Statement::UpdateHash(expr.clone(), offset))
    }
}

impl std::fmt::Display for SolidityCodeGeneratorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(memory offset： {})", self.memory_offset)
    }
}

impl SolidityCodeGeneratorContext {
    pub fn new() -> Self {
        SolidityCodeGeneratorContext {
            absorbing_offset: 0,
            max_absorbing_offset: 0,
            transcript_offset: 0,
            instance_offset: 0,
            tmp_offset: 0,
            memory_offset: 0,
            var_buf: vec![],
            statements: vec![],
            cache: Cache {
                // scalar_constant: HashMap::<BigUint, Rc<Expression>>::new(),
                // point_constant: HashMap::<(BigUint, BigUint), Rc<Expression>>::new(),
                cache_assign: HashMap::<Expression, Rc<Expression>>::new(),
            },
            mock_hash: false,
            transcript_context: false,
            instance_context: false,
        }
    }

    pub(crate) fn allocate(&mut self, t: Type) -> Rc<Expression> {
        let u256_cnt = t.to_length();
        let e = Expression::Memory(self.memory_offset, t);
        self.memory_offset += u256_cnt;
        Rc::new(e)
    }

    pub(crate) fn assign_memory(&mut self, v: Expression, samples: Vec<BigUint>) -> Rc<Expression> {
        match self.cache.cache_assign.get(&v) {
            Some(e) => e.clone(),
            None => {
                let mem = self.allocate(v.get_type());
                if !self.mock_hash {
                    self.cache.cache_assign.insert(v.clone(), mem.clone());
                    self.statements
                        .push(Statement::Assign(mem.clone(), v, samples));
                }
                mem
            }
        }
    }

    pub(crate) fn new_transcript_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::TransciprtOffset(self.transcript_offset, t);
        self.transcript_offset += delta;
        Rc::new(e)
    }

    pub(crate) fn new_instance_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::InstanceOffset(self.instance_offset, t);
        self.instance_offset += delta;
        Rc::new(e)
    }

    pub(crate) fn new_tmp_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::TmpBufOffset(self.tmp_offset, t);
        self.tmp_offset += delta;
        Rc::new(e)
    }

    pub(crate) fn extend_var_buf(&mut self, data: &[u8]) {
        self.var_buf.extend_from_slice(data)
    }
}

pub(crate) struct G2Point {
    pub(crate) x: (BigUint, BigUint),
    pub(crate) y: (BigUint, BigUint),
}

pub(crate) struct CodeGeneratorCtx {
    pub(crate) wx: Expression,
    pub(crate) wg: Expression,
    pub(crate) target_circuit_s_g2: G2Point,
    pub(crate) target_circuit_n_g2: G2Point,
    pub(crate) verify_circuit_s_g2: G2Point,
    pub(crate) verify_circuit_n_g2: G2Point,
    pub(crate) assignments: Vec<Statement>,
    pub(crate) memory_size: usize,
    pub(crate) instance_size: usize,
    pub(crate) absorbing_length: usize,
}
