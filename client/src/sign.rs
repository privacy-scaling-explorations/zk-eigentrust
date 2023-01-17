use ethers::signers::{LocalWallet, Signer, WalletError};
use rand::thread_rng;

pub async fn signs() -> Result<(), WalletError> {
	let rng = &mut thread_rng();
	let wallet = LocalWallet::new(rng);

	let message = "Some data";

	// sign a message
	let signature = wallet.sign_message(message).await?;
	println!("Produced signature {}", signature);

	// verify the signature
	signature.verify(message, wallet.address()).unwrap();

	println!("Verified signature produced by {:?}!", wallet.address());

	Ok(())
}
