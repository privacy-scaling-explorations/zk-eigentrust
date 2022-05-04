use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use libp2p::{
	core::upgrade::write_length_prefixed,
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

#[derive(Clone, Debug)]
pub struct EigenTrustCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
	k: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
	Success {
		local_trust_score: f64,
		global_trust_score: f64,
		product: f64,
	},
	InvalidRequest,
	NeighborNotFound,
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
		io: &mut T,
	) -> Result<Self::Request>
	where
		T: AsyncRead + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let mut buf = [0; 4];
				io.read_exact(&mut buf).await?;
				let k = u32::from_be_bytes(buf);
				Ok(Request { k })
			},
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
				let mut buf = [0; 1];
				io.read_exact(&mut buf).await?;
				let response = match buf[0] {
					0 => {
						let mut local_trust_score = [0; 8];
						let mut global_trust_score = [0; 8];
						let mut product = [0; 8];

						io.read_exact(&mut local_trust_score).await?;
						io.read_exact(&mut global_trust_score).await?;
						io.read_exact(&mut product).await?;

						Response::Success {
							local_trust_score: f64::from_be_bytes(local_trust_score),
							global_trust_score: f64::from_be_bytes(global_trust_score),
							product: f64::from_be_bytes(product),
						}
					},
					1 => Response::InvalidRequest,
					2 => Response::NeighborNotFound,
					other => Response::Other(other),
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
					Response::Success {
						local_trust_score,
						global_trust_score,
						product,
					} => {
						bytes.push(0);
						bytes.extend(local_trust_score.to_be_bytes());
						bytes.extend(global_trust_score.to_be_bytes());
						bytes.extend(product.to_be_bytes());
					},
					Response::InvalidRequest => bytes.push(1),
					Response::NeighborNotFound => bytes.push(2),
					Response::Other(code) => bytes.push(code),
				};
				write_length_prefixed(io, &bytes).await?;
				Ok(())
			},
		}
	}
}
