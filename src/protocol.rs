use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use libp2p::{
	core::upgrade::{read_length_prefixed, write_length_prefixed},
	request_response::{ProtocolName, RequestResponseCodec},
};
use std::io::Result;

#[derive(Debug, Clone)]
pub struct EigenTrustProtocol {
	version: EigenTrustProtocolVersion,
}

impl EigenTrustProtocol {
	pub fn new() -> Self {
		Self {
			version: EigenTrustProtocolVersion::V1,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EigenTrustProtocolVersion {
	V1,
}

#[derive(Clone)]
pub struct EigenTrustCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
	Success,
	Other(u8),
}

impl ProtocolName for EigenTrustProtocol {
	fn protocol_name(&self) -> &[u8] {
		match self.version {
			EigenTrustProtocolVersion::V1 => b"/eigen_trust/1",
		}
	}
}

#[async_trait]
impl RequestResponseCodec for EigenTrustCodec {
	type Protocol = EigenTrustProtocol;
	type Request = Request;
	type Response = Response;

	async fn read_request<T>(
		&mut self,
		protocol: &Self::Protocol,
		_: &mut T,
	) -> Result<Self::Request>
	where
		T: AsyncRead + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => Ok(Request),
		}
	}

	async fn read_response<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
	) -> Result<Self::Response>
	where
		T: AsyncRead + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let status_bytes = read_length_prefixed(io, 1).await?;
				let response = match status_bytes[0] {
					0 => Response::Success,
					code => Response::Other(code),
				};
				Ok(response)
			},
		}
	}

	async fn write_request<T>(
		&mut self,
		protocol: &Self::Protocol,
		_: &mut T,
		_: Self::Request,
	) -> Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => Ok(()),
		}
	}

	async fn write_response<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
		res: Self::Response,
	) -> Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let mut bytes = Vec::new();
				match res {
					Response::Success => bytes.push(0),
					Response::Other(code) => bytes.push(code),
				};
				write_length_prefixed(io, &bytes).await?;
				Ok(())
			},
		}
	}
}
