---
description: A higher level description of Eigen Trust protocol.
---

# Algorithm

The name Eigen Trust originates from the [original paper](https://nlp.stanford.edu/pubs/eigentrust.pdf).

It relates to the way the reputation score is calculated, which is done the following way:

Suppose we have a vector `s` that contains the initial scores for 5 peers:
```
s = [1000, 2000, 500, 300, 200]
```

We will refer to peers by their index in this set. e.g. Peer 0 is a peer on index `0` (which has reputation of `1000`)

Now let's suppose we have an opinion matrix:
```
op0 = [0.0, 0.2, 0.3, 0.5, 0.0] - Peer 0 opinions
op1 = [0.1, 0.0, 0.1, 0.1, 0.7] - Peer 1 opinions
op2 = [0.4, 0.1, 0.0, 0.2, 0.3] - Peer 2 opinions
op3 = [0.1, 0.1, 0.7, 0.0, 0.1] - Peer 3 opinions
op4 = [0.3, 0.1, 0.4, 0.2, 0.0] - Peer 4 opinions
```

The matrix define above describes the distribution of the reputation owned by the peers. Notice that the sum of the distribution of one peer is equal to `1.0`, and we are also not giving ourselves any amount.

Now, let's turn that that distribution into scores:

We take the score of Peer N and multiply it with each element in `op[n]`:
```
sop0 = s[0] * op0 = [  0, 200, 300, 500,    0]
sop1 = s[1] * op1 = [200,   0, 200, 200, 1400]
sop2 = s[2] * op2 = [200,  50,   0, 100,  150]
sop3 = s[3] * op3 = [ 30,  30, 210,   0,   30]
sop4 = s[4] * op4 = [ 60,  20,  80,  40,    0]
```

Now, from this new matrix we can get the new scores for Peer 0:
```
s0 = sop0[0] + sop1[0] + sop2[0] + sop3[0] + sop4[0] = 0 + 200 + 200 + 30 + 60 = 490
```

If we apply the same for formula we can get the new scores for all peers:
```
s = [490, 300, 790, 840, 1580]
```

Notice that amount of reputation in the system is always the same (compare with initial `s`). The reputation cannot be created or destroyed, it can only be allocated.

Everything we did was just one iteration of Eigen Trust algorithm. If we apply the same process throughout several iterations, the reputation score of each peer will not change much further after a certain point. When that happens we say that the reputation scores has **converged.**

Here is an algorithm example written in Rust:
```rust
let mut s: [f32; 5] = [1000., 2000., 500., 300., 200.];

const NUM_ITER: usize = 10;

let op0 = [0.0, 0.2, 0.3, 0.5, 0.0]; // - Peer 0 opinions
let op1 = [0.1, 0.0, 0.1, 0.1, 0.7]; // - Peer 1 opinions
let op2 = [0.4, 0.1, 0.0, 0.2, 0.3]; // - Peer 2 opinions
let op3 = [0.1, 0.1, 0.7, 0.0, 0.1]; // - Peer 3 opinions
let op4 = [0.3, 0.1, 0.4, 0.2, 0.0]; // = Peer 4 opinions

for _ in 0..NUM_ITER {
	// sop0 = s[0] * op0
	let sop0 = op0.map(|v| v * s[0]);
	// sop1 = s[1] * op1
	let sop1 = op1.map(|v| v * s[1]);
	// sop2 = s[2] * op2
	let sop2 = op2.map(|v| v * s[2]);
	// sop3 = s[3] * op3
	let sop3 = op3.map(|v| v * s[3]);
	// sop4 = s[4] * op4
	let sop4 = op4.map(|v| v * s[4]);

	let s0 = sop0[0] + sop1[0] + sop2[0] + sop3[0] + sop4[0];
	let s1 = sop0[1] + sop1[1] + sop2[1] + sop3[1] + sop4[1];
	let s2 = sop0[2] + sop1[2] + sop2[2] + sop3[2] + sop4[2];
	let s3 = sop0[3] + sop1[3] + sop2[3] + sop3[3] + sop4[3];
	let s4 = sop0[4] + sop1[4] + sop2[4] + sop3[4] + sop4[4];

	s = [s0, s1, s2, s3, s4];

	println!("[{}]", s.map(|v| format!("{:>9.4}", v)).join(", "));
}
```

The logs:
```
[490.0000,  300.0000,  790.0000,  840.0000, 1580.0000] - iter 0
[904.0000,  419.0000, 1397.0000,  749.0000,  531.0000] - iter 1
[834.9000,  448.5000, 1049.8000,  879.5000,  787.3000] - iter 2
[788.9100,  438.6400, 1225.8900,  829.7200,  716.8400] - iter 3
[832.2440,  435.0270, 1148.0771,  826.8651,  757.7870] - iter 4
[812.7562,  439.7218, 1175.0963,  840.7976,  731.6286] - iter 5
[817.5791,  437.3035, 1169.0088,  831.6953,  744.4139] - iter 6
[817.8276,  438.0276, 1168.9563,  835.2045,  739.9846] - iter 7
[816.9011,  437.9801, 1169.7881,  834.5048,  740.8266] - iter 8
[817.4117,  437.8922, 1169.3523,  834.3715,  740.9730] - iter 9
```

We can see that only after a few iterations, the scores will converge, depending on how much accuracy is needed.

In the real world, we are working with finite field, so our data structures and algorithm has to be modified a bit.

First we define a constant for a number of iterations:
```rust
const NUM_ITER = 10;
```

Then, the EigenTrust set which includes the inital score for each peer:
```rust
s = [(peer1, 1000), (peer2, 2000), (peer3, 500), (peer4, 300), (peer5, 200)]
```

Now, the scores map:
```rust
scores => {
    peer1 => [(peer1, 0), (peer2, 2), (peer3, 3), (peer4, 5), (peer5, 0)]
    peer2 => [(peer1, 1), (peer2, 0), (peer3, 1), (peer4, 1), (peer5, 7)]
    peer3 => [(peer1, 4), (peer2, 1), (peer3, 0), (peer4, 2), (peer5, 3)]
    peer4 => [(peer1, 1), (peer2, 1), (peer3, 7), (peer4, 0), (peer5, 1)]
    peer5 => [(peer1, 3), (peer2, 1), (peer3, 4), (peer4, 2), (peer5, 0)]
}
```

Minimum number of participants should be 2, if it is less, the matrix would not be able to converge:
```rust
let valid_peers_count = count(filter(s, |s| s.0 != null))
assert!(valid_peers_count >= 2)
```

Before we run the algorithm, we have to normalise the scores:
```rust
// Normalise the scores
for i in 0..s.len() {
    let (pk_i, creadits) = s[i];
    if pk == null {
        continue;
    }
    let sum = sum(scores[pk_i]);
	for j in 0..s.len() {
	    scores[pk_i][j] = scores[pk_i][j] / sum;
    }
}
```

Now, we have conditions to run the EigenTrust algorithm:
```rust
for _ in 0..NUM_ITER {
    for i in 0..s.len() {
        let (pk_i, _) = s[i];
        let new_score = 0;
        if pk_i == null {
            continue;
        }
        for j in 0..s.len() {
            let (pk_j, neighbour_score) = s[j];
            if pk_j == null {
                continue;
            }
            let score = scores[pk_j][i];
            new_score += score * neighbour_score;
        }
        s[i].1 = new_score
    }
}
```
