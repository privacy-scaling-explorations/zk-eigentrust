pub use et_verifier_wrapper::*;
#[allow(clippy::too_many_arguments, non_camel_case_types)]
pub mod et_verifier_wrapper {
	#![allow(clippy::enum_variant_names)]
	#![allow(dead_code)]
	#![allow(clippy::type_complexity)]
	#![allow(unused_imports)]
	use ethers::contract::{
		builders::{ContractCall, Event},
		Contract, Lazy,
	};
	use ethers::core::{
		abi::{Abi, Detokenize, InvalidOutputType, Token, Tokenizable},
		types::*,
	};
	use ethers::providers::Middleware;
	#[doc = "EtVerifierWrapper was auto-generated with ethers-rs Abigen. More information at: https://github.com/gakonst/ethers-rs"]
	use std::sync::Arc;
	# [rustfmt :: skip] const __ABI : & str = "[{\"type\":\"constructor\",\"inputs\":[{\"internalType\":\"address\",\"name\":\"vaddr\",\"type\":\"address\"}]},{\"type\":\"function\",\"name\":\"verify\",\"inputs\":[{\"internalType\":\"uint256[5]\",\"name\":\"pub_ins\",\"type\":\"uint256[5]\"},{\"internalType\":\"bytes\",\"name\":\"proof\",\"type\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"}]" ;
	#[doc = r" The parsed JSON-ABI of the contract."]
	pub static ETVERIFIERWRAPPER_ABI: ethers::contract::Lazy<ethers::core::abi::Abi> =
		ethers::contract::Lazy::new(|| {
			ethers::core::utils::__serde_json::from_str(__ABI).expect("invalid abi")
		});
	pub struct EtVerifierWrapper<M>(ethers::contract::Contract<M>);
	impl<M> Clone for EtVerifierWrapper<M> {
		fn clone(&self) -> Self {
			EtVerifierWrapper(self.0.clone())
		}
	}
	impl<M> std::ops::Deref for EtVerifierWrapper<M> {
		type Target = ethers::contract::Contract<M>;
		fn deref(&self) -> &Self::Target {
			&self.0
		}
	}
	impl<M> std::fmt::Debug for EtVerifierWrapper<M> {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			f.debug_tuple(stringify!(EtVerifierWrapper)).field(&self.address()).finish()
		}
	}
	impl<M: ethers::providers::Middleware> EtVerifierWrapper<M> {
		#[doc = r" Creates a new contract instance with the specified `ethers`"]
		#[doc = r" client at the given `Address`. The contract derefs to a `ethers::Contract`"]
		#[doc = r" object"]
		pub fn new<T: Into<ethers::core::types::Address>>(
			address: T, client: ::std::sync::Arc<M>,
		) -> Self {
			ethers::contract::Contract::new(address.into(), ETVERIFIERWRAPPER_ABI.clone(), client)
				.into()
		}
		#[doc = "Calls the contract's `verify` (0x839ded65) function"]
		pub fn verify(
			&self, pub_ins: [ethers::core::types::U256; 5usize], proof: ethers::core::types::Bytes,
		) -> ethers::contract::builders::ContractCall<M, ()> {
			self.0
				.method_hash([131, 157, 237, 101], (pub_ins, proof))
				.expect("method not found (this should never happen)")
		}
	}
	impl<M: ethers::providers::Middleware> From<ethers::contract::Contract<M>>
		for EtVerifierWrapper<M>
	{
		fn from(contract: ethers::contract::Contract<M>) -> Self {
			Self(contract)
		}
	}
	#[doc = "Container type for all input parameters for the `verify` function with signature `verify(uint256[5],bytes)` and selector `[131, 157, 237, 101]`"]
	#[derive(
		Clone,
		Debug,
		Eq,
		PartialEq,
		ethers :: contract :: EthCall,
		ethers :: contract :: EthDisplay,
		Default,
	)]
	#[ethcall(name = "verify", abi = "verify(uint256[5],bytes)")]
	pub struct VerifyCall {
		pub pub_ins: [ethers::core::types::U256; 5usize],
		pub proof: ethers::core::types::Bytes,
	}
}
