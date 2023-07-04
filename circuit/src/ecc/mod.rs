/// Ecc where both base and scalar fields are emulated
pub mod generic;
/// Ecc where base field is the wrong field and scalar is the native
pub mod same_curve;

use crate::gadgets::main::MainConfig;
use halo2::plonk::Selector;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccAddConfig {
	/// Constructs selectors from different circuits.
	integer_reduce_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccAddConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_reduce_selector: Selector, integer_sub_selector: Selector,
		integer_mul_selector: Selector, integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_reduce_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccDoubleConfig {
	/// Constructs selectors from different circuits.
	integer_reduce_selector: Selector,
	integer_add_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccDoubleConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_reduce_selector: Selector, integer_add_selector: Selector,
		integer_sub_selector: Selector, integer_mul_selector: Selector,
		integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_reduce_selector,
			integer_add_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccUnreducedLadderConfig {
	/// Constructs selectors from different circuits.
	integer_add_selector: Selector,
	integer_sub_selector: Selector,
	integer_mul_selector: Selector,
	integer_div_selector: Selector,
}

impl EccUnreducedLadderConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		integer_add_selector: Selector, integer_sub_selector: Selector,
		integer_mul_selector: Selector, integer_div_selector: Selector,
	) -> Self {
		Self {
			integer_add_selector,
			integer_sub_selector,
			integer_mul_selector,
			integer_div_selector,
		}
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccTableSelectConfig {
	/// Constructs config from main circuit.
	main: MainConfig,
}

impl EccTableSelectConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(main: MainConfig) -> Self {
		Self { main }
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccMulConfig {
	/// Constructs configs and selector from different circuits.
	ladder: EccUnreducedLadderConfig,
	pub(crate) add: EccAddConfig,
	double: EccDoubleConfig,
	table_select: EccTableSelectConfig,
	bits2num: Selector,
}

impl EccMulConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(
		ladder: EccUnreducedLadderConfig, add: EccAddConfig, double: EccDoubleConfig,
		table_select: EccTableSelectConfig, bits2num: Selector,
	) -> Self {
		Self { ladder, add, double, table_select, bits2num }
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct EccBatchedMulConfig {
	/// Constructs configs and selector from different circuits.
	pub(crate) add: EccAddConfig,
	double: EccDoubleConfig,
	bits2num: Selector,
}

impl EccBatchedMulConfig {
	/// Construct a new config
	pub fn new(add: EccAddConfig, double: EccDoubleConfig, bits2num: Selector) -> Self {
		Self { add, double, bits2num }
	}
}
