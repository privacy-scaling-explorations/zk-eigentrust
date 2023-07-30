//! # Filesystem Actions Module.
//!
//! This module provides functionalities for filesystem actions.

use crate::error::EigenError;
use std::{env::current_dir, path::PathBuf};

/// Retrieves the path to the `assets` directory.
pub fn get_assets_path() -> Result<PathBuf, EigenError> {
	current_dir().map_err(EigenError::IOError).map(|current_dir| {
		// Workaround for the tests running in the `client` directory.
		#[cfg(test)]
		{
			current_dir.join("assets")
		}

		#[cfg(not(test))]
		{
			current_dir.join("eigentrust/assets")
		}
	})
}
