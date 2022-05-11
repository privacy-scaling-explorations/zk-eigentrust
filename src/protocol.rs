use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use libp2p::{
	core::upgrade::write_length_prefixed,
	request_response::{ProtocolName, RequestResponseCodec},
};
use std::io::Result;
use crate::peer::Opinion;
use crate::epoch::Epoch;

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
	epoch: Epoch,
}

impl Request {
	pub fn new(epoch: Epoch) -> Self {
		Self { epoch }
	}

	pub fn get_epoch(&self) -> Epoch {
		self.epoch
	}
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
	Success(Opinion),
	InvalidRequest,
	InternalError(u8),
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
				let mut buf = [0; 8];
				io.read_exact(&mut buf).await?;
				let k = u64::from_be_bytes(buf);
				Ok(Request::new(Epoch(k)))
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
						let mut k_bytes = [0; 8];
						let mut local_trust_score_bytes = [0; 8];
						let mut global_trust_score_bytes = [0; 8];
						let mut product_bytes = [0; 8];

						io.read_exact(&mut k_bytes).await?;
						io.read_exact(&mut local_trust_score_bytes).await?;
						io.read_exact(&mut global_trust_score_bytes).await?;
						io.read_exact(&mut product_bytes).await?;

						let k = u64::from_be_bytes(k_bytes);
						let local_trust_score = f64::from_be_bytes(local_trust_score_bytes);
						let global_trust_score = f64::from_be_bytes(global_trust_score_bytes);
						let product = f64::from_be_bytes(product_bytes);

						let opinion = Opinion::new(Epoch(k), local_trust_score, global_trust_score, product);

						Response::Success(opinion)
					},
					1 => Response::InvalidRequest,
					other => Response::InternalError(other),
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
					Response::Success(opinion) => {
						bytes.push(0);
						bytes.extend(opinion.get_epoch().to_be_bytes());
						bytes.extend(opinion.get_local_trust_score().to_be_bytes());
						bytes.extend(opinion.get_global_trust_score().to_be_bytes());
						bytes.extend(opinion.get_product().to_be_bytes());
					},
					Response::InvalidRequest => bytes.push(1),
					Response::InternalError(code) => bytes.push(code),
				};
				write_length_prefixed(io, &bytes).await?;
				Ok(())
			},
		}
	}
}
