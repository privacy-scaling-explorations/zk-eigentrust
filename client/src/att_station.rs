#![allow(clippy::enum_variant_names)]
#![allow(dead_code)]
#![allow(clippy::type_complexity)]
#![allow(unused_imports)]
use ethers::{
	contract::{
		builders::{ContractCall, Event},
		Contract, Lazy,
	},
	core::{
		abi::{Abi, Detokenize, InvalidOutputType, Token, Tokenizable},
		types::*,
	},
	providers::Middleware,
};
#[doc = "AttestationStation was auto-generated with ethers-rs Abigen. More information at: https://github.com/gakonst/ethers-rs"]
use std::sync::Arc;
# [rustfmt :: skip] const __ABI : & str = "[{\"type\":\"function\",\"name\":\"attest\",\"inputs\":[{\"internalType\":\"struct AttestationStation.AttestationData[]\",\"name\":\"_attestations\",\"type\":\"tuple[]\",\"components\":[{\"type\":\"address\"},{\"type\":\"bytes32\"},{\"type\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"attestations\",\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"AttestationCreated\",\"inputs\":[{\"name\":\"creator\",\"type\":\"address\",\"indexed\":true},{\"name\":\"about\",\"type\":\"address\",\"indexed\":true},{\"name\":\"key\",\"type\":\"bytes32\",\"indexed\":true},{\"name\":\"val\",\"type\":\"bytes\",\"indexed\":false}],\"anonymous\":false}]" ;
#[doc = r" The parsed JSON-ABI of the contract."]
pub static ATTESTATIONSTATION_ABI: ethers::contract::Lazy<ethers::core::abi::Abi> =
	ethers::contract::Lazy::new(|| {
		ethers::core::utils::__serde_json::from_str(__ABI).expect("invalid abi")
	});
pub struct AttestationStation<M>(ethers::contract::Contract<M>);
impl<M> Clone for AttestationStation<M> {
	fn clone(&self) -> Self {
		AttestationStation(self.0.clone())
	}
}
impl<M> std::ops::Deref for AttestationStation<M> {
	type Target = ethers::contract::Contract<M>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}
impl<M> std::fmt::Debug for AttestationStation<M> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.debug_tuple(stringify!(AttestationStation)).field(&self.address()).finish()
	}
}
impl<M: ethers::providers::Middleware> AttestationStation<M> {
	#[doc = r" Creates a new contract instance with the specified `ethers`"]
	#[doc = r" client at the given `Address`. The contract derefs to a `ethers::Contract`"]
	#[doc = r" object"]
	pub fn new<T: Into<ethers::core::types::Address>>(
		address: T, client: ::std::sync::Arc<M>,
	) -> Self {
		ethers::contract::Contract::new(address.into(), ATTESTATIONSTATION_ABI.clone(), client)
			.into()
	}

	#[doc = "Calls the contract's `attest` (0x5eb5ea10) function"]
	pub fn attest(
		&self, attestations: ::std::vec::Vec<AttestationData>,
	) -> ethers::contract::builders::ContractCall<M, ()> {
		self.0
			.method_hash([94, 181, 234, 16], attestations)
			.expect("method not found (this should never happen)")
	}

	#[doc = "Calls the contract's `attestations` (0x29b42cb5) function"]
	pub fn attestations(
		&self, p0: ethers::core::types::Address, p1: ethers::core::types::Address, p2: [u8; 32],
	) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Bytes> {
		self.0
			.method_hash([41, 180, 44, 181], (p0, p1, p2))
			.expect("method not found (this should never happen)")
	}

	#[doc = "Gets the contract's `AttestationCreated` event"]
	pub fn attestation_created_filter(
		&self,
	) -> ethers::contract::builders::Event<M, AttestationCreatedFilter> {
		self.0.event()
	}

	#[doc = r" Returns an [`Event`](#ethers_contract::builders::Event) builder for all events of this contract"]
	pub fn events(&self) -> ethers::contract::builders::Event<M, AttestationCreatedFilter> {
		self.0.event_with_filter(Default::default())
	}
}
impl<M: ethers::providers::Middleware> From<ethers::contract::Contract<M>>
	for AttestationStation<M>
{
	fn from(contract: ethers::contract::Contract<M>) -> Self {
		Self(contract)
	}
}
#[derive(
	Clone,
	Debug,
	Eq,
	PartialEq,
	ethers :: contract :: EthEvent,
	ethers :: contract :: EthDisplay,
	Default,
)]
#[ethevent(name = "AttestationCreated", abi = "AttestationCreated(address,address,bytes32,bytes)")]
pub struct AttestationCreatedFilter {
	#[ethevent(indexed)]
	pub creator: ethers::core::types::Address,
	#[ethevent(indexed)]
	pub about: ethers::core::types::Address,
	#[ethevent(indexed)]
	pub key: [u8; 32],
	pub val: ethers::core::types::Bytes,
}
#[doc = "Container type for all input parameters for the `attest` function with signature `attest((address,bytes32,bytes)[])` and selector `[94, 181, 234, 16]`"]
#[derive(
	Clone,
	Debug,
	Eq,
	PartialEq,
	ethers :: contract :: EthCall,
	ethers :: contract :: EthDisplay,
	Default,
)]
#[ethcall(name = "attest", abi = "attest((address,bytes32,bytes)[])")]
pub struct AttestCall {
	pub attestations: ::std::vec::Vec<AttestationData>,
}
#[doc = "Container type for all input parameters for the `attestations` function with signature `attestations(address,address,bytes32)` and selector `[41, 180, 44, 181]`"]
#[derive(
	Clone,
	Debug,
	Eq,
	PartialEq,
	ethers :: contract :: EthCall,
	ethers :: contract :: EthDisplay,
	Default,
)]
#[ethcall(name = "attestations", abi = "attestations(address,address,bytes32)")]
pub struct AttestationsCall(
	pub ethers::core::types::Address,
	pub ethers::core::types::Address,
	pub [u8; 32],
);
#[derive(Debug, Clone, PartialEq, Eq, ethers :: contract :: EthAbiType)]
pub enum AttestationStationCalls {
	Attest(AttestCall),
	Attestations(AttestationsCall),
}
impl ethers::core::abi::AbiDecode for AttestationStationCalls {
	fn decode(data: impl AsRef<[u8]>) -> ::std::result::Result<Self, ethers::core::abi::AbiError> {
		if let Ok(decoded) = <AttestCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
			return Ok(AttestationStationCalls::Attest(decoded));
		}
		if let Ok(decoded) =
			<AttestationsCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
		{
			return Ok(AttestationStationCalls::Attestations(decoded));
		}
		Err(ethers::core::abi::Error::InvalidData.into())
	}
}
impl ethers::core::abi::AbiEncode for AttestationStationCalls {
	fn encode(self) -> Vec<u8> {
		match self {
			AttestationStationCalls::Attest(element) => element.encode(),
			AttestationStationCalls::Attestations(element) => element.encode(),
		}
	}
}
impl ::std::fmt::Display for AttestationStationCalls {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
		match self {
			AttestationStationCalls::Attest(element) => element.fmt(f),
			AttestationStationCalls::Attestations(element) => element.fmt(f),
		}
	}
}
impl ::std::convert::From<AttestCall> for AttestationStationCalls {
	fn from(var: AttestCall) -> Self {
		AttestationStationCalls::Attest(var)
	}
}
impl ::std::convert::From<AttestationsCall> for AttestationStationCalls {
	fn from(var: AttestationsCall) -> Self {
		AttestationStationCalls::Attestations(var)
	}
}
#[doc = "Container type for all return fields from the `attestations` function with signature `attestations(address,address,bytes32)` and selector `[41, 180, 44, 181]`"]
#[derive(
	Clone,
	Debug,
	Eq,
	PartialEq,
	ethers :: contract :: EthAbiType,
	ethers :: contract :: EthAbiCodec,
	Default,
)]
pub struct AttestationsReturn(pub ethers::core::types::Bytes);
#[doc = "`AttestationData(address,bytes32,bytes)`"]
#[derive(
	Clone,
	Debug,
	Default,
	Eq,
	PartialEq,
	ethers :: contract :: EthAbiType,
	ethers :: contract :: EthAbiCodec,
)]
pub struct AttestationData(
	pub ethers::core::types::Address,
	pub [u8; 32],
	pub ethers::core::types::Bytes,
);
