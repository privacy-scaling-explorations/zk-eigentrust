---
description: EigenTrust protocol
---

# EigenTrust

EigenTrust is a reputation-based trust management algorithm that evaluates the trustworthiness of peers in peer-to-peer networks. The algorithm calculates a reputation score for each peer based on feedback from other peers in the network.

The algorithm is based on an opinion matrix that describes the distribution of the reputation owned by the peers in the network. The opinion matrix is used to calculate new scores for each peer, and the process is repeated until the scores converge.

EigenTrust uses a recursive algorithm that involves updating the scores for each peer based on the scores of the other peers in the network. The algorithm is designed to be resilient against collusion and free-riding, two common problems in peer-to-peer networks.

The EigenTrust algorithm can be used in a variety of decentralized decision-making applications, such as decentralized autonomous organizations (DAOs), prediction markets, and reputation systems. It can also be used in peer-to-peer networks to facilitate content discovery and recommendation.

**Main characteristics:**
- Self-policing - the shared ethics of the user groups is defined and enforced by the peers themselves and not by some central authority.

- Incorruptible - Reputation should be obtained by consistent good behavior through several transactions. It is resistant to sybil attack through mechanisms of bootstrapping or sybil rank filtering algorithm.

- Permissonless - New peers can join the system without the permisson of central autorithy, given that they satisfy certain critirea.
