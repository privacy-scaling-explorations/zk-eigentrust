//! # Bandada API module.
//!
//! Bandada API handling module.

use dotenv::{dotenv, var};
use eigen_trust_client::error::EigenError;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::{Client, Response};

/// Bandada API client.
pub struct BandadaApi {
	base_url: String,
	client: Client,
	key: String,
}

impl BandadaApi {
	/// Creates a new `BandadaApi`.
	pub fn new(base_url: &str) -> Result<Self, EigenError> {
		dotenv().ok();
		let key =
			var("BANDADA_API_KEY").map_err(|e| EigenError::ConfigurationError(e.to_string()))?;

		Ok(Self { base_url: base_url.to_string(), client: Client::new(), key })
	}

	/// Adds Member.
	pub async fn add_member(
		&self, group_id: &str, identity_commitment: &str,
	) -> Result<Response, EigenError> {
		let mut headers = HeaderMap::new();
		headers.insert("X-API-KEY", HeaderValue::from_str(&self.key).unwrap());
		headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

		self.client
			.post(&format!(
				"{}/groups/{}/members/{}",
				self.base_url, group_id, identity_commitment
			))
			.headers(headers)
			.send()
			.await
			.map_err(|e| EigenError::RequestError(e.to_string()))
	}

	/// Removes Member.
	pub async fn remove_member(
		&self, group_id: &str, member_id: &str,
	) -> Result<Response, EigenError> {
		let mut headers = HeaderMap::new();
		headers.insert("X-API-KEY", HeaderValue::from_str(&self.key).unwrap());

		self.client
			.delete(&format!(
				"{}/groups/{}/members/{}",
				self.base_url, group_id, member_id
			))
			.headers(headers)
			.send()
			.await
			.map_err(|e| EigenError::RequestError(e.to_string()))
	}
}
