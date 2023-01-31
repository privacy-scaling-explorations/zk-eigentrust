use crate::att_station::{AttestationData as AsData, AttestationStation};
use eigen_trust_circuit::{
	calculate_message_hash,
	eddsa::native::{sign, SecretKey},
	halo2::halo2curves::{bn256::Fr as Scalar, FieldExt},
	utils::to_short,
};
use eigen_trust_protocol::manager::{
	attestation::{Attestation, AttestationData},
	NUM_NEIGHBOURS,
};
use ethers::{
	middleware::SignerMiddleware,
	providers::{Http, Provider},
	signers::LocalWallet,
	types::{Address, Bytes},
};
use std::sync::Arc;

type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub async fn attest(
	client: SignerMiddlewareArc, user_secrets_raw: Vec<[String; 3]>, secret_key: [String; 2],
	ops: [u128; NUM_NEIGHBOURS], as_address: String,
) {
	let user_secrets_vec: Vec<SecretKey> = user_secrets_raw
		.into_iter()
		.map(|x| {
			let sk0_decoded = bs58::decode(&x[1]).into_vec().unwrap();
			let sk1_decoded = bs58::decode(&x[2]).into_vec().unwrap();
			let sk0 = to_short(&sk0_decoded);
			let sk1 = to_short(&sk1_decoded);
			SecretKey::from_raw([sk0, sk1])
		})
		.collect();

	let user_secrets: [SecretKey; NUM_NEIGHBOURS] = user_secrets_vec.try_into().unwrap();
	let user_publics = user_secrets.map(|s| s.public());

	let sk0_bytes = bs58::decode(&secret_key[0]).into_vec().unwrap();
	let sk1_bytes = bs58::decode(&secret_key[1]).into_vec().unwrap();

	let mut sk0: [u8; 32] = [0; 32];
	sk0[..].copy_from_slice(&sk0_bytes);

	let mut sk1: [u8; 32] = [0; 32];
	sk1[..].copy_from_slice(&sk1_bytes);

	let sk = SecretKey::from_raw([sk0, sk1]);
	let pk = sk.public();

	let ops = ops.map(|x| Scalar::from_u128(x));

	let (pks_hash, message_hash) =
		calculate_message_hash::<NUM_NEIGHBOURS, 1>(user_publics.to_vec(), vec![ops.to_vec()]);

	let sig = sign(&sk, &pk, message_hash[0]);

	let att = Attestation::new(sig, pk, user_publics.to_vec(), ops.to_vec());
	let att_data = AttestationData::from(att);
	let bytes = att_data.to_bytes();

	let as_address: Address = as_address.parse().unwrap();
	let as_contract = AttestationStation::new(as_address, client);

	let as_data = AsData(
		Address::zero(),
		pks_hash.to_bytes(),
		Bytes::from(bytes.clone()),
	);
	let as_data_vec = vec![as_data];

	let res = as_contract.attest(as_data_vec).send().await.unwrap().await.unwrap();

	if let Some(receipt) = res {
		println!("Transaction status: {:?}", receipt.status);
	}
}
