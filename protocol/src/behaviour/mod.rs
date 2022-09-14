pub mod req_res;

use libp2p::{
	core::PublicKey,
	identify::{Identify, IdentifyConfig, IdentifyEvent},
	request_response::{
		ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig, RequestResponseEvent,
		ResponseChannel,
	},
	NetworkBehaviour, PeerId,
};
use req_res::{EigenTrustCodec, EigenTrustProtocol, Request, Response};
use std::{iter::once, time::Duration};

const PROTOCOL_VERSION: &str = "eigen_trust/1.0.0";

/// The behaviour of the EigenTrust protocol.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "EigenEvent")]
pub struct EigenTrustBehaviour {
	req_res: RequestResponse<EigenTrustCodec>,
	identify: Identify,
}

/// The events produced by the EigenTrust protocol.
#[derive(Debug)]
pub enum EigenEvent {
	RequestResponse(RequestResponseEvent<Request, Response>),
	Identify(IdentifyEvent),
}

impl From<RequestResponseEvent<Request, Response>> for EigenEvent {
	fn from(v: RequestResponseEvent<Request, Response>) -> Self {
		Self::RequestResponse(v)
	}
}

impl From<IdentifyEvent> for EigenEvent {
	fn from(v: IdentifyEvent) -> Self {
		Self::Identify(v)
	}
}

impl EigenTrustBehaviour {
	/// Constructs a new `EigenTrustBehaviour`.
	pub fn new(
		connection_duration: Duration, interval_duration: Duration, local_public_key: PublicKey,
	) -> Self {
		// Setting up the request/response protocol.
		let protocols = once((EigenTrustProtocol::new(), ProtocolSupport::Full));
		let mut cfg = RequestResponseConfig::default();
		// Keep the connection alive in request/response protocol
		cfg.set_connection_keep_alive(connection_duration);
		// If we failed to get response during the interval duration, cancel it.
		cfg.set_request_timeout(interval_duration);
		let req_proto = RequestResponse::new(EigenTrustCodec, protocols, cfg);

		// Setting up the identify protocol
		let config = IdentifyConfig::new(PROTOCOL_VERSION.to_string(), local_public_key)
			.with_initial_delay(Duration::from_millis(100))
			.with_interval(Duration::from_secs(60 * 60));
		let identify = Identify::new(config);
		Self { req_res: req_proto, identify }
	}

	/// Send response to a request in the request/response protocol.
	pub fn send_response(
		&mut self, channel: ResponseChannel<Response>, response: Response,
	) -> Result<(), Response> {
		self.req_res.send_response(channel, response)
	}

	/// Send a request in the request/response protocol.
	pub fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId {
		self.req_res.send_request(peer_id, request)
	}
}
