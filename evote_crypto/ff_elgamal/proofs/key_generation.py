"""
密钥生成证明

有限域 ElGamal 非交互式零知识证明 - 密钥生成
使用 Schnorr 证明

证明持有者知道公钥 h=g^x 对应的私钥 x。
即证明离散对数的知识：x = log_g(g^x)

对应原 TypeScript 项目中的 src/ff-elgamal/proofs/keyGeneration.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.hash_utils import keccak256
from evote_crypto.ff_elgamal.models import (
    KeyPair,
    SystemParameters,
    is_key_pair,
    is_system_parameters,
)
from evote_crypto.ff_elgamal.proofs.models import KeyGenerationProof


def _generate_challenge(q: int, unique_id: str, h_: int, b: int) -> int:
    """生成挑战值 c = H(uniqueID, h, b) mod q"""
    c = keccak256(unique_id, h_, b)
    return c % q


def generate(
    params: SystemParameters,
    key_pair: KeyPair,
    id: str,
) -> KeyGenerationProof:
    """
    生成密钥生成证明

    步骤：
    1. 生成第二对密钥 (a, b) = (随机值, g^a mod p)
    2. 计算挑战值 c
    3. 计算响应 d = a + c * sk mod q
    """
    is_system_parameters(params)
    is_key_pair(key_pair)

    p, q, g = params.p, params.q, params.g
    h, sk = key_pair.h, key_pair.sk

    a = GlobalHelper.get_secure_random_value(q)
    b = GlobalHelper.pow_bn(g, a, p)  # 承诺

    c = _generate_challenge(q, id, h, b)  # 挑战
    d = GlobalHelper.add_bn(a, GlobalHelper.mul_bn(c, sk, q), q)  # 响应

    return KeyGenerationProof(c=c, d=d)


def verify(
    params: SystemParameters,
    proof: KeyGenerationProof,
    h: int,
    id: str,
) -> bool:
    """
    验证密钥生成证明

    步骤：
    1. 重新计算 b = g^d / h^c mod p
    2. 重新计算挑战值 c'
    3. 验证挑战值是否匹配
    4. 验证 g^d == b * h^c mod p
    """
    is_system_parameters(params)

    p, q, g = params.p, params.q, params.g
    c, d = proof.c, proof.d

    # 重新计算 b = g^d / h^c mod p
    b = GlobalHelper.div_bn(
        GlobalHelper.pow_bn(g, d, p),
        GlobalHelper.pow_bn(h, c, p),
        p,
    )

    # 重新计算挑战值并验证
    c_ = _generate_challenge(q, id, h, b)
    hash_check = GlobalHelper.timing_safe_equal_bn(c, c_)

    # 验证 g^d == b * h^c mod p
    g_pow_d = GlobalHelper.pow_bn(g, d, p)
    bh_pow_c = GlobalHelper.mul_bn(b, GlobalHelper.pow_bn(h, c, p), p)
    d_check = GlobalHelper.timing_safe_equal_bn(g_pow_d, bh_pow_c)

    return hash_check and d_check
