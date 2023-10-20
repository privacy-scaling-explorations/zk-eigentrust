# EigenTrust ZK

This crate contains all the Chips, Chipsets and Circuit related to EigenTrust protocol.
There are 2 main traits that we use to atomically make chips:

1) Chip
```rust
/// Trait for an atomic chip implementation
/// Each chip uses common config columns, but has its own selector
pub trait Chip<F: FieldExt> {
	/// Output of the synthesis
	type Output: Clone;
	/// Gate configuration, using common config columns
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector;
	/// Chip synthesis. This function can return an assigned cell to be used
	/// elsewhere in the circuit
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}
```
Supposed to be the lowest-level primitive and the place where gates are defined.
Specifically, the gates are defined in the `configure` function,
which accepts a `CommonConfig`, and returns a single selector, that will be used to activate this gate.
Example usage:
```rust
/// Structure for the main chip.
pub struct MainChip<F: FieldExt> {
	advice: [AssignedCell<F, F>; NUM_ADVICE],
	fixed: [F; NUM_FIXED],
}

impl<F: FieldExt> MainChip<F> {
	/// Assigns a new witness that is equal to boolean AND of `x` and `y`
	pub fn new(advice: [AssignedCell<F, F>; NUM_ADVICE], fixed: [F; NUM_FIXED]) -> Self {
		Self { advice, fixed }
	}
}

impl<F: FieldExt> Chip<F> for MainChip<F> {
	type Output = ();

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("main gate", |v_cells| {
			// MainGate constraints
			let a = v_cells.query_advice(common.advice[0], Rotation::cur());
			let b = v_cells.query_advice(common.advice[1], Rotation::cur());
			let c = v_cells.query_advice(common.advice[2], Rotation::cur());

			...
		});
		selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "main gate",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.enable(*selector)?;

				// e.g.:
				ctx.assign_advice(common.advice[0], self.advice[0]);

				...
			},
		)
	}
}
```

2) Chipset
```rust
/// Chipset uses a collection of chips as primitives to build more abstract
/// circuits
pub trait Chipset<F: FieldExt> {
	/// Config used for synthesis
	type Config: Clone;
	/// Output of the synthesis
	type Output: Clone;
	/// Chipset synthesis. This function can have multiple smaller chips
	/// synthesised inside. Also can returns an assigned cell.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}
```
Is one level higher that a `Chip` and underneath it should call one or multiple chips.
`Config` should contain the selectors for the underlying chips.
It also accepts `CommonConfig` that will be passed down to chips.
```rust
/// Main config for common primitives like `add`, `mul` ...
#[derive(Debug, Clone)]
pub struct MainConfig {
	selector: Selector,
}

impl MainConfig {
	/// Initialization function for MainConfig
	pub fn new(selector: Selector) -> Self {
		Self { selector }
	}
}

/// Chip for addition operation
pub struct AddChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> AddChipset<F> {
	/// Create new AddChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for AddChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
	    /// e.g.:
		let advices = [self.x, self.y, self.x + self.y, zero, zero];
		let fixed = [F::ONE, F::ONE, -F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "main_add"))?;

		Ok(sum)
	}
}
```

Finally, `CommonConfig` is a predefined struct containing shared set of advice and fixed columns.
Currently, it is fixed to 20 advice, 10 fixed, 1 table and 1 instance column.
```rust
/// Number of advice columns in common config
pub const ADVICE: usize = 20;
/// Number of fixed columns in common config
pub const FIXED: usize = 10;

/// Common config for the whole circuit
#[derive(Clone, Debug)]
pub struct CommonConfig {
	/// Advice columns
	advice: [Column<Advice>; ADVICE],
	/// Fixed columns
	fixed: [Column<Fixed>; FIXED],
	/// Table column
	table: TableColumn,
	/// Instance column
	instance: Column<Instance>,
}

impl CommonConfig {
	/// Create a new `CommonConfig` columns
	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
		let advice = [(); ADVICE].map(|_| meta.advice_column());
		let fixed = [(); FIXED].map(|_| meta.fixed_column());
		let table = meta.lookup_table_column();
		let instance = meta.instance_column();

		advice.map(|c| meta.enable_equality(c));
		fixed.map(|c| meta.enable_constant(c));
		meta.enable_equality(instance);

		Self { advice, fixed, table, instance }
	}
}
```

This config is constructed once in the main circuit and passed down to every chip and chipset.
Example:
```rust
impl SomeCircuit {
    type Config = SomeConfig;

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainChip::configure(&common, meta);
		let bits2num_selector = Bits2NumChip::configure(&common, meta);
		let set_selector = SetChip::configure(&common, meta);
		...
    }
}
```
Each chip that accepts `CommonConfig` has the responsability to pick column that it needs for enforcing constraints.
(NOTE: This is a design flaw - the higher-level circuit should be the one picking the columns based on the requirements of the chips/chipsets.)

Additional utils: `RegionCtx`

RegionCtx is a wrapper around Halo2's vanilla Region API. Example usage:
```rust
let mut ctx = RegionCtx::new(region, 0);
// Enabling selectors
ctx.enable(*selector)?;
// Assign advice columm from instance
let assigned_inst = ctx.assign_from_instance(common.advice[0], common.instance, 0)?;
// Assign from constant
let assigned_one = ctx.assign_from_constant(common.advice[1], F::ONE)?;
// Assign to advice column
let assigned_res = ctx.assign_advice(common.advice[2], some_value)?;
// Copy assign to advice column
let assigned_x = ctx.copy_assign(common.advice[3], self.x)?;
// Assigned to fixed column
let assigned_zero = ctx.assign_fixed(common.fixed[0], F::ZERO)?;
// Constrain equality
ctx.constrain_equal(assigned_x, assigned_zero)?;
// Constrain to constant
ctx.constrain_to_constant(assigned_one, F::ONE)?;
// Move to next row
ctx.next();
// Return back to region
let region = ctx.into_region();
```
