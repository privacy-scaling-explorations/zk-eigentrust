use ark_std::vec::Vec;
use ark_std::Zero;
use rand::Rng;

/// A function for generating random local trust values.
pub fn generate_trust_matrix<R: Rng>(num_peers: usize, rng: &mut R) -> Vec<Vec<f64>> {
	let mut matrix = Vec::new();
	for i in 0..num_peers {
		// Generate a random vector of trust values and add it to the matrix.
		// Also, calculate the sum.
		let mut sum = f64::zero();
		let vals: Vec<f64> = (0..num_peers - 1)
			.map(|_| {
				let rnd_score: f64 = rng.gen_range(0.0..32.);
				sum += rnd_score;
				rnd_score
			})
			.collect();

		// Normalize the vector.
		let mut normalized: Vec<f64> = Vec::with_capacity(num_peers - 1);
		for val in vals {
			normalized.push(val / sum);
		}

		normalized.insert(i as usize, f64::zero());

		// Add the normalized vector to the matrix.
		matrix.push(normalized);
	}

	matrix
}
