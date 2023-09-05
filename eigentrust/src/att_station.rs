//! Auto generated bindings for the AttestationStation contract.
pub use attestation_station::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
	clippy::enum_variant_names, clippy::too_many_arguments, clippy::upper_case_acronyms,
	clippy::type_complexity, dead_code, non_camel_case_types, missing_docs,
	clippy::useless_conversion
)]
pub mod attestation_station {
	#[allow(deprecated)]
	fn __abi() -> ::ethers::core::abi::Abi {
		::ethers::core::abi::ethabi::Contract {
			constructor: ::core::option::Option::None,
			functions: ::core::convert::From::from([
				(
					::std::borrow::ToOwned::to_owned("attest"),
					::std::vec![::ethers::core::abi::ethabi::Function {
						name: ::std::borrow::ToOwned::to_owned("attest"),
						inputs: ::std::vec![::ethers::core::abi::ethabi::Param {
							name: ::std::borrow::ToOwned::to_owned("_attestations"),
							kind: ::ethers::core::abi::ethabi::ParamType::Array(
								::std::boxed::Box::new(
									::ethers::core::abi::ethabi::ParamType::Tuple(::std::vec![
										::ethers::core::abi::ethabi::ParamType::Address,
										::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
										::ethers::core::abi::ethabi::ParamType::Bytes,
									],),
								),
							),
							internal_type: ::core::option::Option::Some(
								::std::borrow::ToOwned::to_owned(
									"struct AttestationStation.AttestationData[]",
								),
							),
						},],
						outputs: ::std::vec![],
						constant: ::core::option::Option::None,
						state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
					},],
				),
				(
					::std::borrow::ToOwned::to_owned("attestations"),
					::std::vec![::ethers::core::abi::ethabi::Function {
						name: ::std::borrow::ToOwned::to_owned("attestations"),
						inputs: ::std::vec![
							::ethers::core::abi::ethabi::Param {
								name: ::std::string::String::new(),
								kind: ::ethers::core::abi::ethabi::ParamType::Address,
								internal_type: ::core::option::Option::Some(
									::std::borrow::ToOwned::to_owned("address"),
								),
							},
							::ethers::core::abi::ethabi::Param {
								name: ::std::string::String::new(),
								kind: ::ethers::core::abi::ethabi::ParamType::Address,
								internal_type: ::core::option::Option::Some(
									::std::borrow::ToOwned::to_owned("address"),
								),
							},
							::ethers::core::abi::ethabi::Param {
								name: ::std::string::String::new(),
								kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize,),
								internal_type: ::core::option::Option::Some(
									::std::borrow::ToOwned::to_owned("bytes32"),
								),
							},
						],
						outputs: ::std::vec![::ethers::core::abi::ethabi::Param {
							name: ::std::string::String::new(),
							kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
							internal_type: ::core::option::Option::Some(
								::std::borrow::ToOwned::to_owned("bytes"),
							),
						},],
						constant: ::core::option::Option::None,
						state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
					},],
				),
			]),
			events: ::core::convert::From::from([(
				::std::borrow::ToOwned::to_owned("AttestationCreated"),
				::std::vec![::ethers::core::abi::ethabi::Event {
					name: ::std::borrow::ToOwned::to_owned("AttestationCreated"),
					inputs: ::std::vec![
						::ethers::core::abi::ethabi::EventParam {
							name: ::std::borrow::ToOwned::to_owned("creator"),
							kind: ::ethers::core::abi::ethabi::ParamType::Address,
							indexed: true,
						},
						::ethers::core::abi::ethabi::EventParam {
							name: ::std::borrow::ToOwned::to_owned("about"),
							kind: ::ethers::core::abi::ethabi::ParamType::Address,
							indexed: true,
						},
						::ethers::core::abi::ethabi::EventParam {
							name: ::std::borrow::ToOwned::to_owned("key"),
							kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize,),
							indexed: true,
						},
						::ethers::core::abi::ethabi::EventParam {
							name: ::std::borrow::ToOwned::to_owned("val"),
							kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
							indexed: false,
						},
					],
					anonymous: false,
				},],
			)]),
			errors: ::std::collections::BTreeMap::new(),
			receive: false,
			fallback: false,
		}
	}
	///The parsed JSON ABI of the contract.
	pub static ATTESTATIONSTATION_ABI: ::ethers::contract::Lazy<::ethers::core::abi::Abi> =
		::ethers::contract::Lazy::new(__abi);
	#[rustfmt::skip]
    const __BYTECODE: &[u8] = b"`\x80`@R4\x80\x15a\0\x10W`\0\x80\xFD[Pa\x069\x80a\0 `\09`\0\xF3\xFE`\x80`@R4\x80\x15a\0\x10W`\0\x80\xFD[P`\x046\x10a\x006W`\x005`\xE0\x1C\x80c)\xB4,\xB5\x14a\0;W\x80c^\xB5\xEA\x10\x14a\0dW[`\0\x80\xFD[a\0Na\0I6`\x04a\x02\x18V[a\0yV[`@Qa\0[\x91\x90a\x02TV[`@Q\x80\x91\x03\x90\xF3[a\0wa\0r6`\x04a\x03\x12V[a\x01#V[\0[`\0` \x81\x81R\x93\x81R`@\x80\x82 \x85R\x92\x81R\x82\x81 \x90\x93R\x82R\x90 \x80Ta\0\xA2\x90a\x04}V[\x80`\x1F\x01` \x80\x91\x04\x02` \x01`@Q\x90\x81\x01`@R\x80\x92\x91\x90\x81\x81R` \x01\x82\x80Ta\0\xCE\x90a\x04}V[\x80\x15a\x01\x1BW\x80`\x1F\x10a\0\xF0Wa\x01\0\x80\x83T\x04\x02\x83R\x91` \x01\x91a\x01\x1BV[\x82\x01\x91\x90`\0R` `\0 \x90[\x81T\x81R\x90`\x01\x01\x90` \x01\x80\x83\x11a\0\xFEW\x82\x90\x03`\x1F\x16\x82\x01\x91[PPPPP\x81V[`\0[\x81Q\x81\x10\x15a\x01\xF8W`\0\x82\x82\x81Q\x81\x10a\x01CWa\x01Ca\x04\xB7V[` \x90\x81\x02\x91\x90\x91\x01\x81\x01Q`@\x80\x82\x01Q3`\0\x90\x81R\x80\x85R\x82\x81 \x84Q`\x01`\x01`\xA0\x1B\x03\x16\x82R\x85R\x82\x81 \x84\x86\x01Q\x82R\x90\x94R\x92 \x90\x92P\x90a\x01\x8C\x90\x82a\x05\x1CV[P\x80` \x01Q\x81`\0\x01Q`\x01`\x01`\xA0\x1B\x03\x163`\x01`\x01`\xA0\x1B\x03\x16\x7F(q\r\xFE\xCA\xB4=\x1E)\xE0*\xA5k.\x1Ea\x0C\x0B\xAE\x19\x13\\\x9C\xF7\xA8:\x1A\xDBm\xF9m\x85\x84`@\x01Q`@Qa\x01\xDD\x91\x90a\x02TV[`@Q\x80\x91\x03\x90\xA4P\x80a\x01\xF0\x81a\x05\xDCV[\x91PPa\x01&V[PPV[\x805`\x01`\x01`\xA0\x1B\x03\x81\x16\x81\x14a\x02\x13W`\0\x80\xFD[\x91\x90PV[`\0\x80`\0``\x84\x86\x03\x12\x15a\x02-W`\0\x80\xFD[a\x026\x84a\x01\xFCV[\x92Pa\x02D` \x85\x01a\x01\xFCV[\x91P`@\x84\x015\x90P\x92P\x92P\x92V[`\0` \x80\x83R\x83Q\x80\x82\x85\x01R`\0[\x81\x81\x10\x15a\x02\x81W\x85\x81\x01\x83\x01Q\x85\x82\x01`@\x01R\x82\x01a\x02eV[P`\0`@\x82\x86\x01\x01R`@`\x1F\x19`\x1F\x83\x01\x16\x85\x01\x01\x92PPP\x92\x91PPV[cNH{q`\xE0\x1B`\0R`A`\x04R`$`\0\xFD[`@Q``\x81\x01g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x82\x82\x10\x17\x15a\x02\xDBWa\x02\xDBa\x02\xA2V[`@R\x90V[`@Q`\x1F\x82\x01`\x1F\x19\x16\x81\x01g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x82\x82\x10\x17\x15a\x03\nWa\x03\na\x02\xA2V[`@R\x91\x90PV[`\0` \x80\x83\x85\x03\x12\x15a\x03%W`\0\x80\xFD[\x825g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x80\x82\x11\x15a\x03=W`\0\x80\xFD[\x81\x85\x01\x91P\x85`\x1F\x83\x01\x12a\x03QW`\0\x80\xFD[\x815\x81\x81\x11\x15a\x03cWa\x03ca\x02\xA2V[\x80`\x05\x1Ba\x03r\x85\x82\x01a\x02\xE1V[\x91\x82R\x83\x81\x01\x85\x01\x91\x85\x81\x01\x90\x89\x84\x11\x15a\x03\x8CW`\0\x80\xFD[\x86\x86\x01\x92P[\x83\x83\x10\x15a\x04pW\x825\x85\x81\x11\x15a\x03\xAAW`\0\x80\x81\xFD[\x86\x01```\x1F\x19\x82\x8D\x03\x81\x01\x82\x13\x15a\x03\xC3W`\0\x80\x81\xFD[a\x03\xCBa\x02\xB8V[a\x03\xD6\x8B\x85\x01a\x01\xFCV[\x81R`@\x84\x81\x015\x8C\x83\x01R\x92\x84\x015\x92\x89\x84\x11\x15a\x03\xF5W`\0\x80\x81\xFD[\x83\x85\x01\x94P\x8E`?\x86\x01\x12a\x04\x0CW`\0\x93P\x83\x84\xFD[\x8B\x85\x015\x93P\x89\x84\x11\x15a\x04\"Wa\x04\"a\x02\xA2V[a\x042\x8C\x84`\x1F\x87\x01\x16\x01a\x02\xE1V[\x92P\x83\x83R\x8E\x81\x85\x87\x01\x01\x11\x15a\x04IW`\0\x80\x81\xFD[\x83\x81\x86\x01\x8D\x85\x017`\0\x93\x83\x01\x8C\x01\x93\x90\x93R\x91\x82\x01R\x83RP\x91\x86\x01\x91\x90\x86\x01\x90a\x03\x92V[\x99\x98PPPPPPPPPV[`\x01\x81\x81\x1C\x90\x82\x16\x80a\x04\x91W`\x7F\x82\x16\x91P[` \x82\x10\x81\x03a\x04\xB1WcNH{q`\xE0\x1B`\0R`\"`\x04R`$`\0\xFD[P\x91\x90PV[cNH{q`\xE0\x1B`\0R`2`\x04R`$`\0\xFD[`\x1F\x82\x11\x15a\x05\x17W`\0\x81\x81R` \x81 `\x1F\x85\x01`\x05\x1C\x81\x01` \x86\x10\x15a\x04\xF4WP\x80[`\x1F\x85\x01`\x05\x1C\x82\x01\x91P[\x81\x81\x10\x15a\x05\x13W\x82\x81U`\x01\x01a\x05\0V[PPP[PPPV[\x81Qg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x15a\x056Wa\x056a\x02\xA2V[a\x05J\x81a\x05D\x84Ta\x04}V[\x84a\x04\xCDV[` \x80`\x1F\x83\x11`\x01\x81\x14a\x05\x7FW`\0\x84\x15a\x05gWP\x85\x83\x01Q[`\0\x19`\x03\x86\x90\x1B\x1C\x19\x16`\x01\x85\x90\x1B\x17\x85Ua\x05\x13V[`\0\x85\x81R` \x81 `\x1F\x19\x86\x16\x91[\x82\x81\x10\x15a\x05\xAEW\x88\x86\x01Q\x82U\x94\x84\x01\x94`\x01\x90\x91\x01\x90\x84\x01a\x05\x8FV[P\x85\x82\x10\x15a\x05\xCCW\x87\x85\x01Q`\0\x19`\x03\x88\x90\x1B`\xF8\x16\x1C\x19\x16\x81U[PPPPP`\x01\x90\x81\x1B\x01\x90UPV[`\0`\x01\x82\x01a\x05\xFCWcNH{q`\xE0\x1B`\0R`\x11`\x04R`$`\0\xFD[P`\x01\x01\x90V\xFE\xA2dipfsX\"\x12 \xB9\xB8>\xD53\xDD<\x1Bo\xF0]\xEFQ[\xD1#\xE7\x7F\xCC{\xCB\xB6\x91\x11\x99%S\xC0\x9E\xC7\"\x12dsolcC\0\x08\x11\x003";
	/// The bytecode of the contract.
	pub static ATTESTATIONSTATION_BYTECODE: ::ethers::core::types::Bytes =
		::ethers::core::types::Bytes::from_static(__BYTECODE);
	#[rustfmt::skip]
    const __DEPLOYED_BYTECODE: &[u8] = b"`\x80`@R4\x80\x15a\0\x10W`\0\x80\xFD[P`\x046\x10a\x006W`\x005`\xE0\x1C\x80c)\xB4,\xB5\x14a\0;W\x80c^\xB5\xEA\x10\x14a\0dW[`\0\x80\xFD[a\0Na\0I6`\x04a\x02\x18V[a\0yV[`@Qa\0[\x91\x90a\x02TV[`@Q\x80\x91\x03\x90\xF3[a\0wa\0r6`\x04a\x03\x12V[a\x01#V[\0[`\0` \x81\x81R\x93\x81R`@\x80\x82 \x85R\x92\x81R\x82\x81 \x90\x93R\x82R\x90 \x80Ta\0\xA2\x90a\x04}V[\x80`\x1F\x01` \x80\x91\x04\x02` \x01`@Q\x90\x81\x01`@R\x80\x92\x91\x90\x81\x81R` \x01\x82\x80Ta\0\xCE\x90a\x04}V[\x80\x15a\x01\x1BW\x80`\x1F\x10a\0\xF0Wa\x01\0\x80\x83T\x04\x02\x83R\x91` \x01\x91a\x01\x1BV[\x82\x01\x91\x90`\0R` `\0 \x90[\x81T\x81R\x90`\x01\x01\x90` \x01\x80\x83\x11a\0\xFEW\x82\x90\x03`\x1F\x16\x82\x01\x91[PPPPP\x81V[`\0[\x81Q\x81\x10\x15a\x01\xF8W`\0\x82\x82\x81Q\x81\x10a\x01CWa\x01Ca\x04\xB7V[` \x90\x81\x02\x91\x90\x91\x01\x81\x01Q`@\x80\x82\x01Q3`\0\x90\x81R\x80\x85R\x82\x81 \x84Q`\x01`\x01`\xA0\x1B\x03\x16\x82R\x85R\x82\x81 \x84\x86\x01Q\x82R\x90\x94R\x92 \x90\x92P\x90a\x01\x8C\x90\x82a\x05\x1CV[P\x80` \x01Q\x81`\0\x01Q`\x01`\x01`\xA0\x1B\x03\x163`\x01`\x01`\xA0\x1B\x03\x16\x7F(q\r\xFE\xCA\xB4=\x1E)\xE0*\xA5k.\x1Ea\x0C\x0B\xAE\x19\x13\\\x9C\xF7\xA8:\x1A\xDBm\xF9m\x85\x84`@\x01Q`@Qa\x01\xDD\x91\x90a\x02TV[`@Q\x80\x91\x03\x90\xA4P\x80a\x01\xF0\x81a\x05\xDCV[\x91PPa\x01&V[PPV[\x805`\x01`\x01`\xA0\x1B\x03\x81\x16\x81\x14a\x02\x13W`\0\x80\xFD[\x91\x90PV[`\0\x80`\0``\x84\x86\x03\x12\x15a\x02-W`\0\x80\xFD[a\x026\x84a\x01\xFCV[\x92Pa\x02D` \x85\x01a\x01\xFCV[\x91P`@\x84\x015\x90P\x92P\x92P\x92V[`\0` \x80\x83R\x83Q\x80\x82\x85\x01R`\0[\x81\x81\x10\x15a\x02\x81W\x85\x81\x01\x83\x01Q\x85\x82\x01`@\x01R\x82\x01a\x02eV[P`\0`@\x82\x86\x01\x01R`@`\x1F\x19`\x1F\x83\x01\x16\x85\x01\x01\x92PPP\x92\x91PPV[cNH{q`\xE0\x1B`\0R`A`\x04R`$`\0\xFD[`@Q``\x81\x01g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x82\x82\x10\x17\x15a\x02\xDBWa\x02\xDBa\x02\xA2V[`@R\x90V[`@Q`\x1F\x82\x01`\x1F\x19\x16\x81\x01g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x82\x82\x10\x17\x15a\x03\nWa\x03\na\x02\xA2V[`@R\x91\x90PV[`\0` \x80\x83\x85\x03\x12\x15a\x03%W`\0\x80\xFD[\x825g\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x80\x82\x11\x15a\x03=W`\0\x80\xFD[\x81\x85\x01\x91P\x85`\x1F\x83\x01\x12a\x03QW`\0\x80\xFD[\x815\x81\x81\x11\x15a\x03cWa\x03ca\x02\xA2V[\x80`\x05\x1Ba\x03r\x85\x82\x01a\x02\xE1V[\x91\x82R\x83\x81\x01\x85\x01\x91\x85\x81\x01\x90\x89\x84\x11\x15a\x03\x8CW`\0\x80\xFD[\x86\x86\x01\x92P[\x83\x83\x10\x15a\x04pW\x825\x85\x81\x11\x15a\x03\xAAW`\0\x80\x81\xFD[\x86\x01```\x1F\x19\x82\x8D\x03\x81\x01\x82\x13\x15a\x03\xC3W`\0\x80\x81\xFD[a\x03\xCBa\x02\xB8V[a\x03\xD6\x8B\x85\x01a\x01\xFCV[\x81R`@\x84\x81\x015\x8C\x83\x01R\x92\x84\x015\x92\x89\x84\x11\x15a\x03\xF5W`\0\x80\x81\xFD[\x83\x85\x01\x94P\x8E`?\x86\x01\x12a\x04\x0CW`\0\x93P\x83\x84\xFD[\x8B\x85\x015\x93P\x89\x84\x11\x15a\x04\"Wa\x04\"a\x02\xA2V[a\x042\x8C\x84`\x1F\x87\x01\x16\x01a\x02\xE1V[\x92P\x83\x83R\x8E\x81\x85\x87\x01\x01\x11\x15a\x04IW`\0\x80\x81\xFD[\x83\x81\x86\x01\x8D\x85\x017`\0\x93\x83\x01\x8C\x01\x93\x90\x93R\x91\x82\x01R\x83RP\x91\x86\x01\x91\x90\x86\x01\x90a\x03\x92V[\x99\x98PPPPPPPPPV[`\x01\x81\x81\x1C\x90\x82\x16\x80a\x04\x91W`\x7F\x82\x16\x91P[` \x82\x10\x81\x03a\x04\xB1WcNH{q`\xE0\x1B`\0R`\"`\x04R`$`\0\xFD[P\x91\x90PV[cNH{q`\xE0\x1B`\0R`2`\x04R`$`\0\xFD[`\x1F\x82\x11\x15a\x05\x17W`\0\x81\x81R` \x81 `\x1F\x85\x01`\x05\x1C\x81\x01` \x86\x10\x15a\x04\xF4WP\x80[`\x1F\x85\x01`\x05\x1C\x82\x01\x91P[\x81\x81\x10\x15a\x05\x13W\x82\x81U`\x01\x01a\x05\0V[PPP[PPPV[\x81Qg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x81\x11\x15a\x056Wa\x056a\x02\xA2V[a\x05J\x81a\x05D\x84Ta\x04}V[\x84a\x04\xCDV[` \x80`\x1F\x83\x11`\x01\x81\x14a\x05\x7FW`\0\x84\x15a\x05gWP\x85\x83\x01Q[`\0\x19`\x03\x86\x90\x1B\x1C\x19\x16`\x01\x85\x90\x1B\x17\x85Ua\x05\x13V[`\0\x85\x81R` \x81 `\x1F\x19\x86\x16\x91[\x82\x81\x10\x15a\x05\xAEW\x88\x86\x01Q\x82U\x94\x84\x01\x94`\x01\x90\x91\x01\x90\x84\x01a\x05\x8FV[P\x85\x82\x10\x15a\x05\xCCW\x87\x85\x01Q`\0\x19`\x03\x88\x90\x1B`\xF8\x16\x1C\x19\x16\x81U[PPPPP`\x01\x90\x81\x1B\x01\x90UPV[`\0`\x01\x82\x01a\x05\xFCWcNH{q`\xE0\x1B`\0R`\x11`\x04R`$`\0\xFD[P`\x01\x01\x90V\xFE\xA2dipfsX\"\x12 \xB9\xB8>\xD53\xDD<\x1Bo\xF0]\xEFQ[\xD1#\xE7\x7F\xCC{\xCB\xB6\x91\x11\x99%S\xC0\x9E\xC7\"\x12dsolcC\0\x08\x11\x003";
	/// The deployed bytecode of the contract.
	pub static ATTESTATIONSTATION_DEPLOYED_BYTECODE: ::ethers::core::types::Bytes =
		::ethers::core::types::Bytes::from_static(__DEPLOYED_BYTECODE);
	pub struct AttestationStation<M>(::ethers::contract::Contract<M>);
	impl<M> ::core::clone::Clone for AttestationStation<M> {
		fn clone(&self) -> Self {
			Self(::core::clone::Clone::clone(&self.0))
		}
	}
	impl<M> ::core::ops::Deref for AttestationStation<M> {
		type Target = ::ethers::contract::Contract<M>;
		fn deref(&self) -> &Self::Target {
			&self.0
		}
	}
	impl<M> ::core::ops::DerefMut for AttestationStation<M> {
		fn deref_mut(&mut self) -> &mut Self::Target {
			&mut self.0
		}
	}
	impl<M> ::core::fmt::Debug for AttestationStation<M> {
		fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
			f.debug_tuple(::core::stringify!(AttestationStation)).field(&self.address()).finish()
		}
	}
	impl<M: ::ethers::providers::Middleware> AttestationStation<M> {
		/// Creates a new contract instance with the specified `ethers` client at
		/// `address`. The contract derefs to a `ethers::Contract` object.
		pub fn new<T: Into<::ethers::core::types::Address>>(
			address: T, client: ::std::sync::Arc<M>,
		) -> Self {
			Self(::ethers::contract::Contract::new(
				address.into(),
				ATTESTATIONSTATION_ABI.clone(),
				client,
			))
		}
		/// Constructs the general purpose `Deployer` instance based on the provided constructor arguments and sends it.
		/// Returns a new instance of a deployer that returns an instance of this contract after sending the transaction
		///
		/// Notes:
		/// - If there are no constructor arguments, you should pass `()` as the argument.
		/// - The default poll duration is 7 seconds.
		/// - The default number of confirmations is 1 block.
		///
		///
		/// # Example
		///
		/// Generate contract bindings with `abigen!` and deploy a new contract instance.
		///
		/// *Note*: this requires a `bytecode` and `abi` object in the `greeter.json` artifact.
		///
		/// ```ignore
		/// # async fn deploy<M: ethers::providers::Middleware>(client: ::std::sync::Arc<M>) {
		///     abigen!(Greeter, "../greeter.json");
		///
		///    let greeter_contract = Greeter::deploy(client, "Hello world!".to_string()).unwrap().send().await.unwrap();
		///    let msg = greeter_contract.greet().call().await.unwrap();
		/// # }
		/// ```
		pub fn deploy<T: ::ethers::core::abi::Tokenize>(
			client: ::std::sync::Arc<M>, constructor_args: T,
		) -> ::core::result::Result<
			::ethers::contract::builders::ContractDeployer<M, Self>,
			::ethers::contract::ContractError<M>,
		> {
			let factory = ::ethers::contract::ContractFactory::new(
				ATTESTATIONSTATION_ABI.clone(),
				ATTESTATIONSTATION_BYTECODE.clone().into(),
				client,
			);
			let deployer = factory.deploy(constructor_args)?;
			let deployer = ::ethers::contract::ContractDeployer::new(deployer);
			Ok(deployer)
		}
		///Calls the contract's `attest` (0x5eb5ea10) function
		pub fn attest(
			&self, attestations: ::std::vec::Vec<AttestationData>,
		) -> ::ethers::contract::builders::ContractCall<M, ()> {
			self.0
				.method_hash([94, 181, 234, 16], attestations)
				.expect("method not found (this should never happen)")
		}
		///Calls the contract's `attestations` (0x29b42cb5) function
		pub fn attestations(
			&self, p0: ::ethers::core::types::Address, p1: ::ethers::core::types::Address,
			p2: [u8; 32],
		) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::Bytes> {
			self.0
				.method_hash([41, 180, 44, 181], (p0, p1, p2))
				.expect("method not found (this should never happen)")
		}
		///Gets the contract's `AttestationCreated` event
		pub fn attestation_created_filter(
			&self,
		) -> ::ethers::contract::builders::Event<::std::sync::Arc<M>, M, AttestationCreatedFilter> {
			self.0.event()
		}
		/// Returns an `Event` builder for all the events of this contract.
		pub fn events(
			&self,
		) -> ::ethers::contract::builders::Event<::std::sync::Arc<M>, M, AttestationCreatedFilter> {
			self.0.event_with_filter(::core::default::Default::default())
		}
	}
	impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
		for AttestationStation<M>
	{
		fn from(contract: ::ethers::contract::Contract<M>) -> Self {
			Self::new(contract.address(), contract.client())
		}
	}
	#[derive(
		Clone,
		::ethers::contract::EthEvent,
		::ethers::contract::EthDisplay,
		Default,
		Debug,
		PartialEq,
		Eq,
		Hash,
	)]
	#[ethevent(
		name = "AttestationCreated",
		abi = "AttestationCreated(address,address,bytes32,bytes)"
	)]
	pub struct AttestationCreatedFilter {
		#[ethevent(indexed)]
		pub creator: ::ethers::core::types::Address,
		#[ethevent(indexed)]
		pub about: ::ethers::core::types::Address,
		#[ethevent(indexed)]
		pub key: [u8; 32],
		pub val: ::ethers::core::types::Bytes,
	}
	///Container type for all input parameters for the `attest` function with signature `attest((address,bytes32,bytes)[])` and selector `0x5eb5ea10`
	#[derive(
		Clone,
		::ethers::contract::EthCall,
		::ethers::contract::EthDisplay,
		Default,
		Debug,
		PartialEq,
		Eq,
		Hash,
	)]
	#[ethcall(name = "attest", abi = "attest((address,bytes32,bytes)[])")]
	pub struct AttestCall {
		pub attestations: ::std::vec::Vec<AttestationData>,
	}
	///Container type for all input parameters for the `attestations` function with signature `attestations(address,address,bytes32)` and selector `0x29b42cb5`
	#[derive(
		Clone,
		::ethers::contract::EthCall,
		::ethers::contract::EthDisplay,
		Default,
		Debug,
		PartialEq,
		Eq,
		Hash,
	)]
	#[ethcall(name = "attestations", abi = "attestations(address,address,bytes32)")]
	pub struct AttestationsCall(
		pub ::ethers::core::types::Address,
		pub ::ethers::core::types::Address,
		pub [u8; 32],
	);
	///Container type for all of the contract's call
	#[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
	pub enum AttestationStationCalls {
		Attest(AttestCall),
		Attestations(AttestationsCall),
	}
	impl ::ethers::core::abi::AbiDecode for AttestationStationCalls {
		fn decode(
			data: impl AsRef<[u8]>,
		) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
			let data = data.as_ref();
			if let Ok(decoded) = <AttestCall as ::ethers::core::abi::AbiDecode>::decode(data) {
				return Ok(Self::Attest(decoded));
			}
			if let Ok(decoded) = <AttestationsCall as ::ethers::core::abi::AbiDecode>::decode(data)
			{
				return Ok(Self::Attestations(decoded));
			}
			Err(::ethers::core::abi::Error::InvalidData.into())
		}
	}
	impl ::ethers::core::abi::AbiEncode for AttestationStationCalls {
		fn encode(self) -> Vec<u8> {
			match self {
				Self::Attest(element) => ::ethers::core::abi::AbiEncode::encode(element),
				Self::Attestations(element) => ::ethers::core::abi::AbiEncode::encode(element),
			}
		}
	}
	impl ::core::fmt::Display for AttestationStationCalls {
		fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
			match self {
				Self::Attest(element) => ::core::fmt::Display::fmt(element, f),
				Self::Attestations(element) => ::core::fmt::Display::fmt(element, f),
			}
		}
	}
	impl ::core::convert::From<AttestCall> for AttestationStationCalls {
		fn from(value: AttestCall) -> Self {
			Self::Attest(value)
		}
	}
	impl ::core::convert::From<AttestationsCall> for AttestationStationCalls {
		fn from(value: AttestationsCall) -> Self {
			Self::Attestations(value)
		}
	}
	///Container type for all return fields from the `attestations` function with signature `attestations(address,address,bytes32)` and selector `0x29b42cb5`
	#[derive(
		Clone,
		::ethers::contract::EthAbiType,
		::ethers::contract::EthAbiCodec,
		Default,
		Debug,
		PartialEq,
		Eq,
		Hash,
	)]
	pub struct AttestationsReturn(pub ::ethers::core::types::Bytes);
	///`AttestationData(address,bytes32,bytes)`
	#[derive(
		Clone,
		::ethers::contract::EthAbiType,
		::ethers::contract::EthAbiCodec,
		Default,
		Debug,
		PartialEq,
		Eq,
		Hash,
	)]
	pub struct AttestationData {
		pub about: ::ethers::core::types::Address,
		pub key: [u8; 32],
		pub val: ::ethers::core::types::Bytes,
	}
}
