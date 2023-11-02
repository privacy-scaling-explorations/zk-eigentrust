---
This page provides an overview of how data is processed after being pulled from AttestationStation. The data stored in AttestationStation is submitted from one user to another, but the EigenTrust algorithm processes opinions from one user to the whole group.
---

To start, a group needs to be defined. This is typically done by assigning a group ID and creating a list of peers, as shown below:
```
group_id = 1377
group = [peer1, peer2, peer3, peer4, peer5]
```


And lets assume we have some attestations in AS already:
```
peer1 => peer2 => 1377 => 5
peer2 => peer3 => 1377 => 7
peer4 => peer2 => 1377 => 3
```

Once the group is defined, the next step is to search AttestationStation to construct an opinion map. This is done by iterating through each peer in the group and searching for relevant attestations. The pseudo code snippet below demonstrates this process:
```rust
for i in 0..group.len() {
    let peer_i = group[i];
    if peer_i == null {
        continue;
    }
    for j in 0..group.len() {
        let peer_j = group[j];

        let is_null = peer_j == null;
        let is_self = peer_i == peer_j;
        if is_null || is_self  {
            continue;
        }

        let att = AS.attestations(peer_i, peer_j, group_id);
        op_map[peer_i][j] = (peer_j, att);
    }
}
```

In this code, `peer_i` and `peer_j` represent two peers in the group, and `AS.attestations(peer_i, peer_j, group_id)` retrieves the attestation between the two peers for the given group ID. The resulting opinion map, stored in the op_map variable, is a two-dimensional array that maps each peer to a list of their attestations with other peers in the group.

Here's an example of what the opinion map might look like, based on the attestations shown earlier:
```
peer1_op => [(peer1, 0), (peer2, 5), (peer3, 0), (peer4, 0), (peer5, 0)]
peer2_op => [(peer1, 0), (peer2, 0), (peer3, 7), (peer4, 0), (peer5, 0)]
peer4_op => [(peer1, 0), (peer2, 3), (peer3, 0), (peer4, 0), (peer5, 0)]
```

This opinion map is then passed to a filtering algorithm before being passed to the EigenTrust algorithm.\
The details of the filtering algorithm are discussed in more detail in the [Dynamic Sets](../3_dynamic_sets.md) page.
