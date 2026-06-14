"""
密钥生成证明

椭圆曲线 ElGamal 非交互式零知识证明 - 密钥生成
使用 Schnorr 证明

证明持有者知道公钥 h = g * sk 对应的私钥 sk。

对应原 TypeScript 项目中的 src/ec-elgamal/proofs/keyGeneration.ts
"""

import hashlib

from evote_crypto import helper as GlobalHelper
from evote_crypto.ec_elgamal.curve import get_curve
from evote_crypto.ec_elgamal.helper import (
    ec_pow,
    ec_mul,
    ec_div,
    curve_points_to_string,
)
from evote_crypto.ec_elgamal.models import CurvePoint, KeyPair, SystemParameters
from evote_crypto.ec_elgamal import system_setup as SystemSetup
from evote_crypto.ec_elgamal.proofs.models import KeyGenerationProof


def generate_challenge(n: int, unique_id: str, h_: CurvePoint, b: CurvePoint) -> int:
    """
    生成挑战值

    c = H(uniqueID || h_ || b) mod n

    使用 SHA-256 作为哈希函数。
    """
    points_str = curve_points_to_string([h_, b])
    input_str = unique_id + points_str
    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()
    c = int.from_bytes(hash_bytes, byteorder="big")
    return c % n


def generate(
    params: SystemParameters,
    share: KeyPair,
    id: str,
) -> KeyGenerationProof:
    """
    生成密钥生成证明

    步骤：
    1. 生成第二对密钥 (a, b)
    2. 计算挑战值 c
    3. 计算响应 d = a + c * sk mod n
    """
    n = params.n
    h, sk = share.h, share.sk

    # 生成第二对密钥
    key_pair = SystemSetup.generate_key_pair()
    a = key_pair.sk
    b = key_pair.h

    c = generate_challenge(n, id, h, b)
    d = GlobalHelper.add_bn(a, GlobalHelper.mul_bn(c, sk, n), n)

    return KeyGenerationProof(c=c, d=d)


def verify(
    params: SystemParameters,
    proof: KeyGenerationProof,
    h_: CurvePoint,
    id: str,
) -> bool:
    """
    验证密钥生成证明

    步骤：
    1. 重新计算 b = g * d - h * c
    2. 重新计算挑战值 c'
    3. 验证挑战值是否匹配
    4. 验证 g * d == b + h * c
    """
    n, g = params.n, params.g
    c, d = proof.c, proof.d

    # 重新计算 b = g^d / h^c = g*d - h*c
    b = ec_div(ec_pow(g, d), ec_pow(h_, c))

    # 重新计算挑战值并验证
    c_ = generate_challenge(n, id, h_, b)
    hash_check = c == c_

    # 验证 g*d == b + h*c
    g_pow_d = ec_pow(g, d)
    bh_pow_c = ec_mul(b, ec_pow(h_, c))
    d_check = g_pow_d.x == bh_pow_c.x and g_pow_d.y == bh_pow_c.y

    return hash_check and d_check
