/// Absorb the rescue-poseidon hash sponge
pub mod absorb;
/// Convert integer to bits
pub mod bits2integer;
/// Convert number to bits
pub mod bits2num;
/// Check if a number is less than or equal to a value
pub mod lt_eq;
/// Common gadget for the optimization
pub mod main;
/// Set membership gadget
pub mod set;

/* NOTE:
   Following chipsets are not used atm because of column limits.
   Currently, the maximum columns for EigenTrust circuit is 8 advice + 5 fixed.
   We plan to use them when lookup table can be used in circuit.
*/
/// Check if a number is less than or equal to a value (using lookup table)
pub mod lt_eq_lookup;
/// Range check gadget (using lookup table)
pub mod range;
