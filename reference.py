'''
Ref: http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf
'''

import secrets
import random

from typing import List, Tuple, NewType, Dict


TMatrix = List[List[float]]
TVector = List[float]


def eigentrust_central(num_peers: int, local_trust_matrix: TMatrix, initial_trust_scores: TVector):
    """
    Algorithm 1 in section 4.3.
    """
    delta = 0.01

    def transpose(t: TMatrix) -> TMatrix:
        return [
            [ t[j][i] for j in range(len(row))]
            for i, row in enumerate(t)
        ]

    def get_matrix_size(a: TMatrix) -> Tuple[int, int]:
        m = len(a)
        if m == 0:
            raise ValueError
        n = len(a[0])
        if n == 0:
            raise ValueError
        return (m, n)

    def matrix_mul(a: TMatrix, b: TMatrix) -> TMatrix:
        assert is_matrix_multipiable(a, b)
        m, na = get_matrix_size(a)
        _, l = get_matrix_size(b)
        return [
            [sum([a[i][k] * b[k][j] for k in range(na)]) for j in range(l)]
            for i in range(m)
        ]

    def is_matrix_multipiable(a: TMatrix, b: TMatrix):
        _, na = get_matrix_size(a)
        nb, _ = get_matrix_size(b)
        return na == nb

    def get_vector_distance(a: TMatrix, b: TMatrix):
        if len(b) != len(a):
            raise ValueError
        s = 0
        for index, row_a in enumerate(a):
            row_b = b[index]
            if len(row_a) != 1 or len(row_b) != 1:
                raise ValueError
            s += pow(row_a[0] - row_b[0], 2)
        return pow(s, 0.5)

    ct = transpose(local_trust_matrix)
    t_matrix: TMatrix = [[i] for i in initial_trust_scores]
    # FIXME: If something goes wrong here we get a infinite loop XD
    while 1:
        new_t = matrix_mul(ct, t_matrix)
        if get_vector_distance(t_matrix, new_t) < delta:
            break
        t_matrix = new_t
    return [row[0] for row in new_t]


def eigentrust_distributed(num_peers: int, local_trust_matrix: TMatrix, initial_trust_scores: TVector):
    """
    A simple version of the algorithm 3, in section 4.6.
    """
    delta = 0.001
    TPeerScore = NewType('TPeerScore', float)
    TPeerIndex = NewType('TPeerIndex', int)

    class Peer:
        index: TPeerIndex
        neighbours: Dict[TPeerIndex, 'Peer']
        local_trust_values: Dict[TPeerIndex, TPeerScore]
        # Global trust value for myself
        ti: TPeerScore
        last_cij_ti: Dict[TPeerIndex, TPeerScore]
        is_converged: bool

        def __init__(self, index: TPeerIndex) -> None:
            self.index = index
            self.neighbours = {}
            self.local_trust_values = {}
            self.last_cij_ti = {}
            self.ti = 0
            self.is_converged = False

        def add_neighbour(self, peer: 'Peer', local_trust_value: TPeerScore, pretrust_score: TPeerScore) -> None:
            self.neighbours[peer.index] = peer
            self.local_trust_values[peer.index] = local_trust_value
            self.last_cij_ti[peer.index] = pretrust_score

        def heartbeat(self) -> None:
            if self.is_converged:
                return

            new_ti = TPeerScore(0.0)
            for j, neighbour_j in self.neighbours.items():
                # Compute `t_i(k+1) = (1 - a)*(c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)) + a*p_i`
                # We haven't considered `a` here.
                if self.index not in neighbour_j.last_cij_ti:
                    continue
                new_ti += TPeerScore(neighbour_j.last_cij_ti[self.index])
            # Send c_ij * t_i(k+1)to all peers j
            for j in self.neighbours.keys():
                self.last_cij_ti[j] = TPeerScore(self.local_trust_values[j] * new_ti)
            if abs(new_ti - self.ti) <= delta:
                self.is_converged = True
            self.ti = new_ti

    class Network:
        size: TPeerIndex
        peers: Tuple['Peer', ...]
        is_converged: bool

        def __init__(self, size: TPeerIndex) -> None:
            self.size = size
            self.peers = self._gen_peers(size)
            self.is_converged = False

        def _gen_peers(self, size: TPeerIndex) -> Tuple['Peer', ...]:
            return tuple(
                Peer(TPeerIndex(i)) for i in range(size)
            )

        def _connect_peers(self, local_trust_matrix: TMatrix) -> None:
            for i, c_i in enumerate(local_trust_matrix):
                for j, c_ij in enumerate(c_i):
                    if i == j:
                        continue
                    self.peers[i].add_neighbour(self.peers[j], c_ij, initial_trust_scores[j])

        def tick(self):
            # Randomly choose an order to perform heartbeats
            peer_list = list(self.peers)
            # random.shuffle(peer_list)
            # Become `True` when all peers are converged
            is_not_all_converged = True
            for peer in peer_list:
                peer.heartbeat()
                is_not_all_converged = is_not_all_converged and peer.is_converged
            self.is_converged = is_not_all_converged

        def get_global_trust_scores(self) -> TVector:
            t = sum([peer.ti for peer in self.peers])
            return [peer.ti / t for peer in self.peers]

    network = Network(num_peers)
    network._connect_peers(local_trust_matrix)

    while not network.is_converged:
        network.tick()

    return network.get_global_trust_scores()


def gen_trust_matrix(num_peers: int) -> TMatrix:
    # i, j = 0
    # sum(row) = 1
    # For each row, get `num_peers - 1` values, and normalize them.
    mat = []
    for i in range(num_peers):
        random_ints = [secrets.randbelow(32) for _ in range(num_peers - 1)]
        s = sum(random_ints)
        normalized = [j / s for j in random_ints]
        normalized.insert(i, 0)
        mat.append(normalized)
    return mat


def print_matrix(c: TMatrix):
    print('=' * (len(c) * 20))
    for row in c:
        print(',\t'.join([str(i) for i in row]))
    print('=' * (len(c) * 20))


def main():
    num_peers_str = input('Enter number of peers\n')
    num_peers = int(num_peers_str)
    initial_trust_scores = [1/num_peers for i in range(num_peers)]
    print('initial_trust_scores = ', initial_trust_scores)
    # c = gen_trust_matrix(num_peers)
    c = [
        [0.,	0.,	0.9333333333333333,	0.06666666666666667],
        [0.4727272727272727,	0.,	0.03636363636363636,	0.4909090909090909],
        [0.3695652173913043,	0.3695652173913043,	0.,	0.2608695652173913],
        [0.15625,	0.4375,	0.40625,	0.],
    ]
    print('number of peers = ', num_peers)
    print('local reputation matrix is generated randomly:')
    print_matrix(c)

    res_central = eigentrust_central(num_peers, c, initial_trust_scores)
    res_distributed = eigentrust_distributed(num_peers, c, initial_trust_scores)

    print(f'res_central\t= {res_central}')
    print(f'res_distributed\t= {res_distributed}')

main()