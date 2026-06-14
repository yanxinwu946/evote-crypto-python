"""
解密证明

椭圆曲线 ElGamal 非交互式零知识证明 - 解密
使用 Chaum-Pedersen 证明

证明解密操作使用了与加密公钥对应的私钥。

对应原 TypeScript 项目中的 src/ec-elgamal/proofs/decryption.ts
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
from evote_crypto.ec_elgamal.proofs.models import DecryptionProof


def generate_challenge(
    n: int,
    id: str,
    a: CurvePoint,
    b: CurvePoint,
    a1: CurvePoint,
    b1: CurvePoint,
) -> int:
    """
    生成挑战值

    c = H(id || a || b || a1 || b1) mod n
    """
    points_str = curve_points_to_string([a, b, a1, b1])
    input_str = id + points_str
    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()
    c = int.from_bytes(hash_bytes, byteorder="big")
    return c % n


def generate(
    cipher: Cipher,
    params,
    sk: int,
    id: str,
    log: bool = False,
) -> DecryptionProof:
    """
    生成解密证明

    步骤：
    1. 生成随机值 x
    2. 计算 (a1, b1) = (a^x, g^x)
    3. 生成挑战值
    4. 计算 f = x + c * sk mod n
    5. 计算解密因子 d = a^sk
    """
    a, b = cipher.a, cipher.b
    g, n = deserialize_params(params).g, deserialize_params(params).n

    x = GlobalHelper.get_secure_random_value(n)

    a1 = ec_pow(a, x)
    b1 = ec_pow(g, x)

    c = generate_challenge(n, id, a, b, a1, b1)
    f = GlobalHelper.add_bn(x, GlobalHelper.mul_bn(c, sk, n), n)
    d = ec_pow(a, sk)

    if log:
        curve = get_curve()
        print(f"a1 在曲线上?\t{curve.validate(a1)}")
        print(f"b1 在曲线上?\t{curve.validate(b1)}")
        print(f"d 在曲线上?\t{curve.validate(d)}")

    return DecryptionProof(a1=a1, b1=b1, f=f, d=d)


def verify(
    encrypted_sum: Cipher,
    proof: DecryptionProof,
    params,
    pk,
    id: str,
    log: bool = False,
) -> bool:
    """
    验证解密证明

    步骤：
    1. 重新计算挑战值
    2. 验证 a^f == a1 * d^c
    3. 验证 g^f == b1 * h^c
    """
    a, b = encrypted_sum.a, encrypted_sum.b
    g, n = deserialize_params(params).g, deserialize_params(params).n
    pk = deserialize_curve_point(pk)
    a1, b1, f, d = proof.a1, proof.b1, proof.f, proof.d

    c = generate_challenge(n, id, a, b, a1, b1)

    # 验证 a^f == a1 * d^c
    l1 = ec_pow(a, f)
    r1 = ec_mul(a1, ec_pow(d, c))
    v1 = l1.x == r1.x and l1.y == r1.y

    # 验证 g^f == b1 * h^c
    l2 = ec_pow(g, f)
    r2 = ec_mul(b1, ec_pow(pk, c))
    v2 = l2.x == r2.x and l2.y == r2.y

    return v1 and v2
