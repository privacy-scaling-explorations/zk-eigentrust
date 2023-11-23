---
This page describes the AttestationStation smart contract and how its used within the EigenTrust protocol context.
---

# AttestationStation

The AttestationStation smart contract is a key component of the EigenTrust protocol, which is designed to enable trust among peers in decentralized networks. Attestations, also known as opinions or ratings, are an important part of the protocol as they allow peers to express their trust or distrust of other peers. The AttestationStation contract serves as a repository for attestations submitted by peers in the network.

Examples (Let's assume we are doing ratings from 0-5):
- Alice attests Bob with a rating of 5
- Alice attests to Carol with a rating of 2
- Bob attests to Alice with a rating of 3
- Carol says Bob with a rating of 4
- Alice attests Bob with a rating of 1

The mapping attestations is a 3-dimensional mapping that stores attestations submitted by peers. The first key is the address of the peer submitting the attestation. The second key is the address of the peer being attested to. The third key is a bytes32 hash representing the transaction or interaction between the peers. The value stored in the mapping is a bytes array representing the attestation data.
```solidity
mapping(address => mapping(address => mapping(bytes32 => bytes))) public attestations;
```

The AttestationData struct represents an attestation submitted by a peer. The `about` field is the address of the peer being attested to. The `key` field is a bytes32 hash representing the transaction or interaction between the peers. The `val` field is a bytes array representing the attestation data. The structure of the `val` field is described in more detail in the [Attestations](../1_attestations.md) documentation.
```solidity
struct AttestationData {
    address about;
    bytes32 key;
    bytes val;
}
```
