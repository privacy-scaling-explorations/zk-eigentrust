use num::Float;
use rand::Rng;

/// A function for generating random local trust values.
pub fn generate_trust_matrix<R: Rng, S: Float>(num_peers: usize, rng: &mut R) -> Vec<Vec<S>> {
    let mut matrix = Vec::new();
    for i in 0..num_peers {
        // Generate a random vector of trust values and add it to the matrix.
        // Also, calculate the sum.
        let mut sum = S::zero();
        let vals: Vec<S> = (0..num_peers - 1)
            .map(|_| {
                let rnd_score: f64 = rng.gen_range(0.0..32.);
                let score = S::from(rnd_score).unwrap();
                sum = sum + score;
                score
            })
            .collect();

        // Normalize the vector.
        let mut normalized: Vec<S> = Vec::with_capacity(num_peers - 1);
        for val in vals {
            normalized.push(val / sum);
        }

        normalized.insert(i as usize, S::zero());

        // Add the normalized vector to the matrix.
        matrix.push(normalized);
    }

    matrix
}
