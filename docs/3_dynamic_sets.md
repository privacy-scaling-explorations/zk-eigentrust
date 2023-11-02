---
This page describes our dynamic sets filtering algorithm.
---

Suppose we create a fixed set of peers with a limit of 5.\
Instead of using Ethereum addresses we will use simplified identifiers
like peer1, peer2, peer3, etc. and we will use `null` for empty slots.

This set will change over time as we will be able to add and remove members.

For example, let's say we have the following set of peers:
```
set = [peer1, peer2, peer3, null, null]
```

Now, imagine we have a map that represent opinions from one peer to the whole group. Every opinion should match the set to be valid, in the following way:
```
peer1 => [(peer1, 0), (peer2, 4), (peer3, 6), (null, 0), (null, 0)]
```
The opinion array should equal the original set in length.\
The items in the array are touples of the id of the peer that we want to give the score to and the actual score. The id at each index should match the id in the set in order to be considered valid.

The whole map should look like this:
```
scores => {
    peer1 => [(peer1, 0), (peer2, 4), (peer3, 6), (null, 0), (null, 0)]
    peer2 => [(peer1, 4), (peer2, 0), (peer3, 6), (null, 0), (null, 0)]
    peer3 => [(peer1, 4), (peer2, 6), (peer3, 0), (null, 0), (null, 0)]
}
```

Now, let's take a look at how we filter out invalid cases from the opinion array.

**Filtering of invalid cases:**

1) Id at the specific index does not match the one in the set:\
Suppose we want to give a score of 5 to peer13 at the index 3:
```
peer1 => [(peer1, 0), (peer2, 4), (peer3, 6), (peer13, 5), (null, 0)]
```
Since the id at index 3 is null, the id and the score will be nullified, and the new opinion will look like:
```
peer1 => [(peer1, 0), (peer2, 4), (peer3, 6), (null, 0), (null, 0)]
```

2) Non 0 score was given to itself:\
Giving score to itself is forbiden since peers would be able to give the score only to themselves, thus introducing reputation leaking during the convergence.
So, this type of opinion:
```
peer1 => [(peer1, 4), (peer2, 0), (peer3, 6), (null, 0), (null, 0)]
```
will turn into:
```
peer1 => [(peer1, 0), (peer2, 0), (peer3, 6), (null, 0), (null, 0)]
```

3) Total sum of scores is 0:\
If the initial opinion, or the filtered opinion has a sum of scores of 0,
the equal score (score of 1) is given to each peer, so this:
```
peer1 => [(peer1, 0), (peer2, 0), (peer3, 0), (null, 0), (null, 0)]
```
will turn into this:
```
peer1 => [(peer1, 0), (peer2, 1), (peer3, 1), (null, 0), (null, 0)]
```

4) Opinion array does not exist/not signed:\
Will be treated the same way as 3). The equal score will be distributed to all peers

The pseudo code algorithm:
```rust
for i in set.len() {
    let pk_i = set[i];
    if pk_i == null {
        continue;
    }

    for j in set.len() {
        let pk_j = set[j];
        let op_pk_j = scores[pk_i][j].0;

        let is_diff_pk_j = pk_j != op_pk_j;
        let is_pk_j_zero = pk_j == null;
        let is_pk_i = pk_j == pk_i;

        if is_diff_pk_j || is_pk_j_zero || is_pk_i {
            scores[pk_i][j].1 = 0;
        }

        if is_diff_pk_j {
            scores[pk_i][j].0 = pk_j;
        }
    }

    let op_score_sum = sum(scores[pk_i]);
    if op_score_sum == 0 {
        for j in 0..group.len() {
            let pk_j = scores[pk_i][j].0;

            let is_diff_pk = pk_j != pk_i;
            let is_not_null = pk_j != null;

            if is_diff_pk && is_not_null {
                scores[pk_i][j] = (pk_j, Fr::from(1));
            }
        }
    }
}
```
