// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Verifier {
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        uint256 length = p1.length * 6;
        uint256[] memory input = new uint256[](length);
        uint256[1] memory result;
        bool ret;

        require(p1.length == p2.length);

        for (uint256 i = 0; i < p1.length; i++) {
            input[0 + i * 6] = p1[i].x;
            input[1 + i * 6] = p1[i].y;
            input[2 + i * 6] = p2[i].x[0];
            input[3 + i * 6] = p2[i].x[1];
            input[4 + i * 6] = p2[i].y[0];
            input[5 + i * 6] = p2[i].y[1];
        }

        assembly {
            ret := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(length, 0x20),
                result,
                0x20
            )
        }
        require(ret);
        return result[0] != 0;
    }

    uint256 constant q_mod =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function fr_invert(uint256 a) internal view returns (uint256) {
        return fr_pow(a, q_mod - 2);
    }

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = q_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_div(uint256 a, uint256 b) internal view returns (uint256) {
        require(b != 0);
        return mulmod(a, fr_invert(b), q_mod);
    }

    function fr_mul_add(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return addmod(mulmod(a, b, q_mod), c, q_mod);
    }

    function fr_mul_add_pm(
        uint256[{{memory_size}}] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                t = addmod(mulmod(proof[a], m[b], q_mod), t, q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_mul_add_mt(
        uint256[{{memory_size}}] memory m,
        uint256 base,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 1) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                t = addmod(mulmod(base, t, q_mod), m[a], q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }

    uint256 constant p_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function ecc_from(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory r)
    {
        r.x = x;
        r.y = y;
    }

    function ecc_add(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        bool ret = false;
        G1Point memory r;
        uint256[4] memory input_points;

        input_points[0] = ax;
        input_points[1] = ay;
        input_points[2] = bx;
        input_points[3] = by;

        assembly {
            ret := staticcall(gas(), 6, input_points, 0x80, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function ecc_sub(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        return ecc_add(ax, ay, bx, p_mod - by);
    }

    function ecc_mul(uint256 px, uint256 py, uint256 s)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[3] memory input;
        bool ret = false;
        G1Point memory r;

        input[0] = px;
        input[1] = py;
        input[2] = s;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function _ecc_mul_add(uint256[5] memory input)
        internal
        view
    {
        bool ret = false;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, add(input, 0x20), 0x40)
        }
        require(ret);

        assembly {
            ret := staticcall(gas(), 6, add(input, 0x20), 0x80, add(input, 0x60), 0x40)
        }
        require(ret);
    }

    function ecc_mul_add(uint256 px, uint256 py, uint256 s, uint256 qx, uint256 qy)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[5] memory input;
        input[0] = px;
        input[1] = py;
        input[2] = s;
        input[3] = qx;
        input[4] = qy;

        _ecc_mul_add(input);

        return (input[3], input[4]);
    }
    
    function ecc_mul_add_pm(
        uint256[{{memory_size}}] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t0,
        uint256 t1
    ) internal view returns (uint256, uint256) {
        uint256[5] memory input;
        input[3] = t0;
        input[4] = t1;
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                input[0] = proof[a];
                input[1] = proof[a + 1];
                input[2] = m[b];
                _ecc_mul_add(input);
            } else {
                break;
            }
        }

        return (input[3], input[4]);
    }

    function update_hash_scalar(uint256 v, uint256[{{absorbing_length + 1}}] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(uint256 x, uint256 y, uint256[{{absorbing_length + 1}}] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v = tmp % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[{{absorbing_length + 1}}] memory absorbing, uint256 length) private view returns (bytes32[1] memory v) {
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 2, absorbing, length, v, 32)
            switch success case 0 { invalid() }
        }
        assert(success);
    }

    function squeeze_challenge(uint256[{{absorbing_length + 1}}] memory absorbing, uint32 length) internal view returns (uint256 v) {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_verify_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256({{verify_circuit_s_g2_x0}});
        s.x[1] = uint256({{verify_circuit_s_g2_x1}});
        s.y[0] = uint256({{verify_circuit_s_g2_y0}});
        s.y[1] = uint256({{verify_circuit_s_g2_y1}});
    }

    function get_verify_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256({{verify_circuit_n_g2_x0}});
        n.x[1] = uint256({{verify_circuit_n_g2_x1}});
        n.y[0] = uint256({{verify_circuit_n_g2_y0}});
        n.y[1] = uint256({{verify_circuit_n_g2_y1}});
    }

    function get_target_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256({{target_circuit_s_g2_x0}});
        s.x[1] = uint256({{target_circuit_s_g2_x1}});
        s.y[0] = uint256({{target_circuit_s_g2_y0}});
        s.y[1] = uint256({{target_circuit_s_g2_y1}});
    }

    function get_target_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256({{target_circuit_n_g2_x0}});
        n.x[1] = uint256({{target_circuit_n_g2_x1}});
        n.y[0] = uint256({{target_circuit_n_g2_y0}});
        n.y[1] = uint256({{target_circuit_n_g2_y1}});
    }

    function get_wx_wg(uint256[] calldata proof, uint256[{{instance_size}}] memory instances)
        internal
        view
        returns (uint256, uint256, uint256, uint256)
    {
        uint256[{{memory_size}}] memory m;
        uint256[{{absorbing_length + 1}}] memory absorbing;
        uint256 t0 = 0;
        uint256 t1 = 0;

        {% for statement in statements %}
        {{statement}}
        {%- endfor %}
        return ({{ wx }}, {{ wg }});
    }

    function verify(
        uint256[] calldata proof,
        uint256[] calldata target_circuit_final_pair
    ) public view {
        uint256[{{instance_size}}] memory instances;
        instances[0] = target_circuit_final_pair[0] & ((1 << 136) - 1);
        instances[1] = (target_circuit_final_pair[0] >> 136) + ((target_circuit_final_pair[1] & 1) << 136);
        instances[2] = target_circuit_final_pair[2] & ((1 << 136) - 1);
        instances[3] = (target_circuit_final_pair[2] >> 136) + ((target_circuit_final_pair[3] & 1) << 136);
        {% for statement in instance_assign %}
        {{statement}}
        {%- endfor %}

        uint256 x0 = 0;
        uint256 x1 = 0;
        uint256 y0 = 0;
        uint256 y1 = 0;

        G1Point[] memory g1_points = new G1Point[](2);
        G2Point[] memory g2_points = new G2Point[](2);
        bool checked = false;

        (x0, y0, x1, y1) = get_wx_wg(proof, instances);
        g1_points[0].x = x0;
        g1_points[0].y = y0;
        g1_points[1].x = x1;
        g1_points[1].y = y1;
        g2_points[0] = get_verify_circuit_g2_s();
        g2_points[1] = get_verify_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);

        g1_points[0].x = target_circuit_final_pair[0];
        g1_points[0].y = target_circuit_final_pair[1];
        g1_points[1].x = target_circuit_final_pair[2];
        g1_points[1].y = target_circuit_final_pair[3];
        g2_points[0] = get_target_circuit_g2_s();
        g2_points[1] = get_target_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);
    }
}
