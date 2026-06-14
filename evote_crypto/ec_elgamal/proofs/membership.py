"""
成员证明

椭圆曲线 ElGamal 非交互式零知识证明 - 明文成员资格
使用析取 Chaum-Pedersen 证明

证明加密的投票值确实是 0 或 1，同时不揭示实际值。

对应原 TypeScript 项目中的 src/ec-elgamal/proofs/membership.ts
"""

import hashlib

from evote_crypto import helper as GlobalHelper
from evote_crypto.ec_elgamal.curve import get_curve
from evote_crypto.ec_elgamal.helper import (
    ec_pow,
    ec_mul,
    ec_div,
    curve_points_to_string,
    deserialize_curve_point,
    deserialize_params,
)
from evote_crypto.ec_elgamal.models import (
    Cipher,
    CurvePoint,
    SystemParameters,
)
from evote_crypto.ec_elgamal.proofs.models import MembershipProof


def generate_challenge(
    n: int,
    id: str,
    c1: CurvePoint,
    c2: CurvePoint,
    a1: CurvePoint,
    a2: CurvePoint,
    b1: CurvePoint,
    b2: CurvePoint,
) -> int:
    """
    生成挑战值

    c = H(id || c1 || c2 || a1 || a2 || b1 || b2) mod n
    """
    points_str = curve_points_to_string([c1, c2, a1, a2, b1, b2])
    input_str = id + points_str
    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()
    c = int.from_bytes(hash_bytes, byteorder="big")
    return c % n


def generate_yes_proof(
    encrypted_vote: Cipher,
    params,
    public_key,
    id: str,
) -> MembershipProof:
    """
    为加密的赞成投票生成证明

    步骤：
    1. 为 m=0 生成伪造值 c0, f0（Z_n 中的随机值）
    2. 计算伪造的 (a0, b0) = (g^f0 - a^c0, h^f0 - b^c0)
    3. 为 m=1 生成真实证明
       3.1 生成随机值 x ∈ Z_n
       3.2 计算 (a1, b1) = (g^x, h^x)
    4. 生成挑战值 c
    5. 计算 c1 = c - c0 mod n
    6. 计算 f1 = x + c1 * r mod n
    """
    g, n = deserialize_params(params).g, deserialize_params(params).n
    h = deserialize_curve_point(public_key)
    a, b, r = encrypted_vote.a, encrypted_vote.b, encrypted_vote.r

    if r is None:
        raise ValueError("随机数 r 未定义")

    c0 = GlobalHelper.get_secure_random_value(n)
    f0 = GlobalHelper.get_secure_random_value(n)

    a0 = ec_div(ec_pow(g, f0), ec_pow(a, c0))
    b0 = ec_div(ec_pow(h, f0), ec_pow(b, c0))

    x = GlobalHelper.get_secure_random_value(n)
    a1 = ec_pow(g, x)
    b1 = ec_pow(h, x)

    c = generate_challenge(n, id, a, b, a0, b0, a1, b1)
    c1 = GlobalHelper.add_bn(n, GlobalHelper.sub_bn(c, c0, n), n)

    f1 = GlobalHelper.add_bn(x, GlobalHelper.mul_bn(c1, r, n), n)

    return MembershipProof(
        a0=a0, a1=a1, b0=b0, b1=b1,
        c0=c0, c1=c1, f0=f0, f1=f1,
    )


def generate_no_proof(
    encrypted_vote: Cipher,
    params,
    public_key,
    id: str,
) -> MembershipProof:
    """
    为加密的反对投票生成证明

    步骤：
    1. 为 m=1 生成伪造值 c1, f1（Z_n 中的随机值）
    2. 计算伪造的 b_ = b - g
    3. 计算伪造的 (a1, b1) = (g^f1 - a^c1, h^f1 - (b-g)^c1)
    4. 为 m=0 生成真实证明
       4.1 生成随机值 x ∈ Z_n
       4.2 计算 (a0, b0) = (g^x, h^x)
    5. 生成挑战值 c
    6. 计算 c0 = c - c1 mod n
    7. 计算 f0 = x + c0 * r mod n
    """
    g, n = deserialize_params(params).g, deserialize_params(params).n
    h = deserialize_curve_point(public_key)
    a, b, r = encrypted_vote.a, encrypted_vote.b, encrypted_vote.r

    if r is None:
        raise ValueError("随机数 r 未定义")

    c1 = GlobalHelper.get_secure_random_value(n)
    f1 = GlobalHelper.get_secure_random_value(n)

    b_ = ec_div(b, g)

    a1 = ec_div(ec_pow(g, f1), ec_pow(a, c1))
    b1 = ec_div(ec_pow(h, f1), ec_pow(b_, c1))

    x = GlobalHelper.get_secure_random_value(n)
    a0 = ec_pow(g, x)
    b0 = ec_pow(h, x)

    c = generate_challenge(n, id, a, b, a0, b0, a1, b1)
    c0 = GlobalHelper.add_bn(n, GlobalHelper.sub_bn(c, c1, n), n)

    f0 = GlobalHelper.add_bn(x, GlobalHelper.mul_bn(c0, r, n), n)

    return MembershipProof(
        a0=a0, a1=a1, b0=b0, b1=b1,
        c0=c0, c1=c1, f0=f0, f1=f1,
    )


def verify(
    encrypted_vote: Cipher,
    proof: MembershipProof,
    params,
    public_key,
    id: str,
) -> bool:
    """
    验证成员证明

    验证：
    1. g^f0 == a0 * a^c0
    2. g^f1 == a1 * a^c1
    3. h^f0 == b0 * b^c0
    4. h^f1 == b1 * (b-g)^c1
    5. c == c1 + c0（重新计算哈希验证）
    """
    a0, a1 = proof.a0, proof.a1
    b0, b1 = proof.b0, proof.b1
    c0, c1 = proof.c0, proof.c1
    f0, f1 = proof.f0, proof.f1

    g, n = deserialize_params(params).g, deserialize_params(params).n
    h = deserialize_curve_point(public_key)
    a, b = encrypted_vote.a, encrypted_vote.b

    def _eq(p1: CurvePoint, p2: CurvePoint) -> bool:
        return p1.x == p2.x and p1.y == p2.y

    v1 = _eq(ec_pow(g, f0), ec_mul(a0, ec_pow(a, c0)))
    v2 = _eq(ec_pow(g, f1), ec_mul(a1, ec_pow(a, c1)))
    v3 = _eq(ec_pow(h, f0), ec_mul(b0, ec_pow(b, c0)))
    v4 = _eq(
        ec_pow(h, f1),
        ec_mul(b1, ec_pow(ec_div(b, g), c1)),
    )
    v5 = GlobalHelper.add_bn(c0, c1, n) == generate_challenge(
        n, id, a, b, a0, b0, a1, b1
    )

    return v1 and v2 and v3 and v4 and v5
