"""
成员证明

有限域 ElGamal 非交互式零知识证明 - 明文成员资格
使用析取 Chaum-Pedersen 证明

证明两个陈述中有一个为真，但不揭示哪个是正确的。
这里用于证明加密的投票（0 或 1）确实是 0 或 1，
同时不揭示投票的实际值。

对应原 TypeScript 项目中的 src/ff-elgamal/proofs/membership.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.hash_utils import keccak256
from evote_crypto.ff_elgamal.models import (
    Cipher,
    SystemParameters,
    is_cipher,
    is_system_parameters,
)
from evote_crypto.ff_elgamal.proofs.models import MembershipProof


def _add(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.add_bn(a, b, sp.q)


def _sub(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.sub_bn(a, b, sp.q)


def _mul(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.mul_bn(a, b, sp.p)


def _div(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.div_bn(a, b, sp.p)


def _pow(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.pow_bn(a, b, sp.p)


def _generate_challenge(
    q: int,
    unique_id: str,
    a: int,
    b: int,
    a0: int,
    b0: int,
    a1: int,
    b1: int,
) -> int:
    """生成挑战值 c = H(uniqueID, a, b, a0, b0, a1, b1) mod q"""
    c = keccak256(unique_id, a, b, a0, b0, a1, b1)
    return c % q


def generate_yes_proof(
    cipher: Cipher,
    sp: SystemParameters,
    pk: int,
    unique_id: str,
) -> MembershipProof:
    """
    为加密的赞成投票生成证明

    步骤：
    1. 为 m=0 生成伪造值 c0, f0（Z_q 中的随机值）
    2. 计算伪造的 (a0, b0) = (g^f0 / a^c0, h^f0 / b^c0)
    3. 为 m=1 生成真实证明
       3.1 生成随机值 x ∈ Z_q
       3.2 计算 (a1, b1) = (g^x, h^x)
    4. 生成挑战值 c
    5. 计算 c1 = c - c0
    6. 计算 f1 = x + c1 * r mod q
    """
    is_cipher(cipher)
    is_system_parameters(sp)

    a, b, r = cipher.a, cipher.b, cipher.r

    c0 = GlobalHelper.get_secure_random_value(sp.q)
    f0 = GlobalHelper.get_secure_random_value(sp.q)

    a0 = _div(_pow(sp.g, f0, sp), _pow(a, c0, sp), sp)
    b0 = _div(_pow(pk, f0, sp), _pow(b, c0, sp), sp)

    x = GlobalHelper.get_secure_random_value(sp.q)
    a1 = _pow(sp.g, x, sp)
    b1 = _pow(pk, x, sp)

    c = _generate_challenge(sp.q, unique_id, a, b, a0, b0, a1, b1)
    c1 = _add(sp.q, _sub(c, c0, sp), sp)

    f1 = _add(x, (c1 * r) % sp.q, sp)

    return MembershipProof(
        a0=a0, a1=a1, b0=b0, b1=b1,
        c0=c0, c1=c1, f0=f0, f1=f1,
    )


def generate_no_proof(
    cipher: Cipher,
    sp: SystemParameters,
    pk: int,
    unique_id: str,
) -> MembershipProof:
    """
    为加密的反对投票生成证明

    步骤：
    1. 为 m=1 生成伪造值 c1, f1（Z_q 中的随机值）
    2. 计算伪造的 b_ = b/g
    3. 计算伪造的 (a1, b1) = (g^f1 / a^c1, h^f1 / (b/g)^c1)
    4. 为 m=0 生成真实证明
       4.1 生成随机值 x ∈ Z_q
       4.2 计算 (a0, b0) = (g^x, h^x)
    5. 生成挑战值 c
    6. 计算 c0 = c - c1
    7. 计算 f0 = x + c0 * r mod q
    """
    is_cipher(cipher)
    is_system_parameters(sp)

    a, b, r = cipher.a, cipher.b, cipher.r

    c1 = GlobalHelper.get_secure_random_value(sp.q)
    f1 = GlobalHelper.get_secure_random_value(sp.q)

    b_ = _div(b, sp.g, sp)

    a1 = _div(_pow(sp.g, f1, sp), _pow(a, c1, sp), sp)
    b1 = _div(_pow(pk, f1, sp), _pow(b_, c1, sp), sp)

    x = GlobalHelper.get_secure_random_value(sp.q)
    a0 = _pow(sp.g, x, sp)
    b0 = _pow(pk, x, sp)

    c = _generate_challenge(sp.q, unique_id, a, b, a0, b0, a1, b1)
    c0 = _add(sp.q, _sub(c, c1, sp), sp)

    f0 = _add(x, (c0 * r) % sp.q, sp)

    return MembershipProof(
        a0=a0, a1=a1, b0=b0, b1=b1,
        c0=c0, c1=c1, f0=f0, f1=f1,
    )


def verify(
    cipher: Cipher,
    proof: MembershipProof,
    sp: SystemParameters,
    pk: int,
    unique_id: str,
) -> bool:
    """
    验证成员证明

    验证：
    1. g^f0 == a0 * a^c0 mod p
    2. g^f1 == a1 * a^c1 mod p
    3. h^f0 == b0 * b^c0 mod p
    4. h^f1 == b1 * (b/g)^c1 mod p
    5. c == c1 + c0 (重新计算哈希验证)
    """
    is_cipher(cipher)
    is_system_parameters(sp)

    a, b = cipher.a, cipher.b
    a0, a1 = proof.a0, proof.a1
    b0, b1 = proof.b0, proof.b1
    c0, c1 = proof.c0, proof.c1
    f0, f1 = proof.f0, proof.f1

    v1 = GlobalHelper.timing_safe_equal_bn(
        _pow(sp.g, f0, sp), _mul(a0, _pow(a, c0, sp), sp)
    )
    v2 = GlobalHelper.timing_safe_equal_bn(
        _pow(sp.g, f1, sp), _mul(a1, _pow(a, c1, sp), sp)
    )
    v3 = GlobalHelper.timing_safe_equal_bn(
        _pow(pk, f0, sp), _mul(b0, _pow(b, c0, sp), sp)
    )
    v4 = GlobalHelper.timing_safe_equal_bn(
        _pow(pk, f1, sp),
        _mul(b1, _pow(_div(b, sp.g, sp), c1, sp), sp),
    )
    v5 = GlobalHelper.timing_safe_equal_bn(
        (c1 + c0) % sp.q,
        _generate_challenge(sp.q, unique_id, a, b, a0, b0, a1, b1),
    )

    return v1 and v2 and v3 and v4 and v5
