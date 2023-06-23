//! # Bandada API module.
//!
//! Bandada API handling module.

use dotenv::{dotenv, var};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::{Client, Error, Response};

/// Base URL for the Bandada API.
pub const BASE_URL: &str = "http://localhost:3000"; // "https://bandada.appliedzkp.org/api"

/// Bandada API client.
pub struct BandadaApi {
	client: Client,
	key: String,
}

impl BandadaApi {
	/// Creates a new `BandadaApi`.
	pub fn new() -> Result<Self, &'static str> {
		dotenv().ok();
		let key = var("BANDADA_API_KEY")
			.map_err(|_| "BANDADA_API_KEY environment variable is not set.")?;

		Ok(Self { client: Client::new(), key })
	}

	/// Adds Member.
	pub async fn add_member(
		&self, group_id: &str, identity_commitment: &str,
	) -> Result<Response, Error> {
		let mut headers = HeaderMap::new();
		headers.insert("X-API-KEY", HeaderValue::from_str(&self.key).unwrap());
		headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

		self.client
			.post(&format!(
				"{}/groups/{}/members/{}",
				BASE_URL, group_id, identity_commitment
			))
			.headers(headers)
			.send()
			.await
	}

	/// Removes Member.
	pub async fn remove_member(&self, group_id: &str, member_id: &str) -> Result<Response, Error> {
		let mut headers = HeaderMap::new();
		headers.insert("X-API-KEY", HeaderValue::from_str(&self.key).unwrap());

		self.client
			.delete(&format!(
				"{}/groups/{}/members/{}",
				BASE_URL, group_id, member_id
			))
			.headers(headers)
			.send()
			.await
	}
}
