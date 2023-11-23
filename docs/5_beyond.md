---
description: This pages explores future directions for EigenTrust.
---

Several problems to be solved:
1) Non-unique peer identifiers:\
If there are two or more peers with the same identifier in the set, the filtering algorithm will not work as intended. To avoid this, it is important to use unique identifiers for each peer.
We can achieve this by requiring the set to have unique id associated with it. This can be achieved by compressing all the peers ids into a MerkleTree root/Sponge hash outside the circuit and make constraints inside the circuit.
For example, consider a set:
```rust
s = [(peer1, 1000), (peer2, 2000), (peer3, 500), (peer4, 300), (peer5, 200)]
```

We can extract the peer ids from this set, and construct the unique id for the whole set
```rust
s_ids = s.map(|x| x.0)
root_hash = construct_merkle_tree(s_ids)
// OR
final_hash = poseidon_sponge_hash(s_ids)
```
Then we can pass `root_hash` or `final_hash` into the circuit as a public input. We would re-construct the same tree/sponge hash inside the circuit and compare with the public input.

2) Performance considerations:\
As the size of the set and the opinion map grows, the filtering algorithm can become computationally expensive. To optimize performance, it may be necessary to use more efficient data structures and algorithms.
One way we could fix this is to split the network into smaller ones. So, have predefined groups of maximum 256 peers for which we can make EigenTrust convergence proofs. We can then aggregate 2 or more of these proofs to form larger groups.

If we have sets with `N` participants, aggregating `M` number of proofs, would result in `N * M` number of participants.
```rust
s1 = ([peer1_score, peer2_score, peer3_score], proof_1)
s2 = ([peer4_score, peer5_score, peer6_score], proof_2)
s3 = ([peer7_score, peer8_score, peer9_score], proof_3)

accumulator_limbs = aggregate(s1, s2, s3)

verify(accumulator_limbs)
```

We can also do multiple levels of aggregation in form of a Merkle Tree until we reach the root, where we have aggregated the whole network.

Future directions - Integration with smart contract platforms:
1) Peers can use these proofs to prove their reputation and use them to join communities such as Semaphore groups or similar working groups. We can generalise this to make gate-keeping for any form of action on any protocol.
2) We can also integrate EigenTrust sets inside the smart contract itself. The converged scores of each participants can be used for reputation-weighted voting inside this smart contract.
