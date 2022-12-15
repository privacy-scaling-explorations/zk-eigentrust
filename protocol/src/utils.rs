use crate::{error::EigenError, manager::ivp::Posedion5x5};
use eigen_trust_circuit::halo2wrong::{
	curves::{bn256::Fr as Scalar, FieldExt},
	halo2::arithmetic::Field,
	utils::decompose,
};
use futures::{
	stream::{self, BoxStream, Fuse},
	StreamExt,
};
use rand::RngCore;
use tokio::time::{self, Duration, Instant};

/// Write an array of 32 elements into an array of 64 elements.
pub fn to_wide(p: [u8; 32]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..32].copy_from_slice(&p[..]);
	res
}

/// Write a byte array into an array of 64 elements.
pub fn to_wide_bytes(p: &[u8]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..p.len()].copy_from_slice(p);
	res
}

pub fn scalar_from_bs58(key: &str) -> Scalar {
	let bytes = &bs58::decode(key).into_vec().unwrap();
	Scalar::from_bytes_wide(&to_wide_bytes(bytes))
}

/// Schedule `num` intervals with a duration of `interval` that starts at
/// `start`.
pub fn create_iter<'a>(start: Instant, interval: Duration, num: usize) -> Fuse<BoxStream<'a, u32>> {
	let mut inner_interval = time::interval_at(start, interval);
	inner_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
	stream::unfold((inner_interval, 0), |(mut interval, count)| async move {
		interval.tick().await;
		Some((count, (interval, count + 1)))
	})
	.take(num)
	.boxed()
	.fuse()
}
