pub mod req_res;

use crate::{peer::Peer, Epoch};
use libp2p::{
	core::PublicKey,
	identify::{Identify, IdentifyConfig, IdentifyEvent},
	request_response::{
		ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig, RequestResponseEvent,
		RequestResponseMessage, ResponseChannel,
	},
	swarm::NetworkBehaviourEventProcess,
	NetworkBehaviour, PeerId,
};
use req_res::{EigenTrustCodec, EigenTrustProtocol, Request, Response};
use std::{iter::once, time::Duration};

const PROTOCOL_VERSION: &str = "eigen_trust/1.0.0";

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct EigenTrustBehaviour {
	req_res: RequestResponse<EigenTrustCodec>,
	identify: Identify,
	#[behaviour(ignore)]
	peer: Peer,
}

impl EigenTrustBehaviour {
	pub fn new(
		connection_duration: Duration,
		interval_duration: Duration,
		local_public_key: PublicKey,
		peer: Peer,
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
			.with_initial_delay(Duration::from_millis(0));
		let identify = Identify::new(config);
		Self {
			req_res: req_proto,
			identify,
			peer,
		}
	}

	pub fn send_response(
		&mut self,
		channel: ResponseChannel<Response>,
		response: Response,
	) -> Result<(), Response> {
		self.req_res.send_response(channel, response)
	}

	pub fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId {
		self.req_res.send_request(peer_id, request)
	}

	/// Get the peer struct.
	pub fn get_peer(&self) -> &Peer {
		&self.peer
	}

	/// Get the mutable peer struct.
	pub fn get_peer_mut(&mut self) -> &mut Peer {
		&mut self.peer
	}

	/// Send the request for an opinion to all neighbors, in the passed epoch.
	pub fn send_epoch_requests(&mut self, epoch: Epoch) {
		for peer_id in self.peer.neighbors() {
			let request = Request::new(epoch);
			self.req_res.send_request(&peer_id, request);
		}
	}

	pub fn global_trust_score_at(&self, at: Epoch) -> f64 {
		self.peer.calculate_global_trust_score(at)
	}
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<Request, Response>> for EigenTrustBehaviour {
	fn inject_event(&mut self, event: RequestResponseEvent<Request, Response>) {
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message {
				peer,
				message: Req {
					request, channel, ..
				},
			} => {
				// First we calculate the local opinions for the requested epoch.
				self.peer.calculate_local_opinions(request.get_epoch());
				self.peer.calculate_local_proof(request.get_epoch());
				// Then we send the local opinion to the peer.
				let opinion = self.peer.get_local_opinion(&(peer, request.get_epoch()));
				let proof = self.peer.get_local_proof(request.get_epoch());
				let response = Response::Success(opinion, proof);
				let res = self.req_res.send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message {
				peer,
				message: Res { response, .. },
			} => {
				// If we receive a response, we update the neighbors's opinion about us.
				if let Response::Success(opinion, proof) = response {
					self.peer.cache_neighbor_opinion((peer, opinion.k), opinion);
					self.peer.cache_neighbor_proof((peer, opinion.k), proof);
				} else {
					log::error!("Received error response {:?}", response);
				}
			},
			OutboundFailure {
				peer, request_id, ..
			} => {
				log::error!("Outbound failure {:?} from {:?}", request_id, peer);
			},
			InboundFailure {
				peer, request_id, ..
			} => {
				log::error!("Inbound failure {:?} from {:?}", request_id, peer);
			},
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			},
		};
	}
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for EigenTrustBehaviour {
	fn inject_event(&mut self, event: IdentifyEvent) {
		match event {
			IdentifyEvent::Received { peer_id, info } => {
				self.peer.identify_neighbor(peer_id, info.public_key);
				log::info!("Neighbor identified {:?}", peer_id);
			},
			IdentifyEvent::Sent { peer_id } => {
				log::debug!("Identify request sent to {:?}", peer_id);
			},
			IdentifyEvent::Pushed { peer_id } => {
				log::debug!("Identify request pushed to {:?}", peer_id);
			},
			IdentifyEvent::Error { peer_id, error } => {
				log::error!("Identify error {:?} from {:?}", error, peer_id);
			},
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::Peer;
	use eigen_trust_circuit::halo2wrong::halo2::poly::{
		commitment::ParamsProver, kzg::commitment::ParamsKZG,
	};
	use libp2p::{core::identity::Keypair, identify::IdentifyInfo};
	use tokio::time::Duration;

	#[test]
	fn should_handle_identify_events() {
		let connection_duration = Duration::from_secs(86400 * 365 * 30);
		let interval_duration = Duration::from_secs(10);
		let local_key = Keypair::generate_secp256k1();

		let params = ParamsKZG::new(1);
		let peer = Peer::new(local_key.clone(), params);
		let mut beh = EigenTrustBehaviour::new(
			connection_duration,
			interval_duration,
			local_key.public(),
			peer,
		);

		let sender_key = Keypair::generate_secp256k1();
		let sender_pubkey = sender_key.public();
		let sender_peer_id = sender_pubkey.to_peer_id();

		let identity_info = IdentifyInfo {
			public_key: sender_pubkey.clone(),
			protocol_version: "proto_version".to_owned(),
			agent_version: "agent_version".to_owned(),
			listen_addrs: vec![
				"/ip4/80.81.82.83/tcp/500".parse().unwrap(),
				"/ip6/::1/udp/1000".parse().unwrap(),
			],
			protocols: vec!["proto1".to_string(), "proto2".to_string()],
			observed_addr: "/ip4/100.101.102.103/tcp/5000".parse().unwrap(),
		};

		beh.inject_event(IdentifyEvent::Received {
			peer_id: sender_peer_id,
			info: identity_info,
		});

		assert_eq!(beh.peer.get_pub_key(sender_peer_id), sender_pubkey);
	}
}
