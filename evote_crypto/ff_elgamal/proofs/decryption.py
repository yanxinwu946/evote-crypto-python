"""
解密证明

有限域 ElGamal 非交互式零知识证明 - 解密
使用 Chaum-Pedersen 证明

证明解密操作使用了与加密公钥对应的私钥。

对应原 TypeScript 项目中的 src/ff-elgamal/proofs/decryption.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.hash_utils import keccak256
from evote_crypto.ff_elgamal.models import (
    Cipher,
    SystemParameters,
    is_cipher,
    is_system_parameters,
)
from evote_crypto.ff_elgamal.proofs.models import DecryptionProof


def _add(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.add_bn(a, b, sp.q)


def _mul(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.mul_bn(a, b, sp.p)


def _pow(a: int, b: int, sp: SystemParameters) -> int:
    return GlobalHelper.pow_bn(a, b, sp.p)


def _generate_challenge(
    q: int, unique_id: str, a: int, b: int, a1: int, b1: int
) -> int:
    """生成挑战值 c = H(uniqueID, a, b, a1, b1) mod q"""
    c = keccak256(unique_id, a, b, a1, b1)
    return c % q


def generate(
    cipher: Cipher,
    sp: SystemParameters,
    sk: int,
    unique_id: str,
) -> DecryptionProof:
    """
    生成解密证明

    步骤：
    1. 生成随机值 x
    2. 计算 (a1, b1) = (a^x, g^x)
    3. 生成挑战值
    4. 计算 f = x + c * sk mod q
    5. 计算解密因子 d = a^sk
    """
    is_cipher(cipher)
    is_system_parameters(sp)

    a, b = cipher.a, cipher.b

    x = GlobalHelper.get_secure_random_value(sp.q)

    a1 = _pow(a, x, sp)
    b1 = _pow(sp.g, x, sp)

    c = _generate_challenge(sp.q, unique_id, a, b, a1, b1)
    f = _add(x, (c * sk) % sp.q, sp)
    d = _pow(a, sk, sp)

    return DecryptionProof(a1=a1, b1=b1, f=f, d=d)


def verify(
    cipher: Cipher,
    proof: DecryptionProof,
    sp: SystemParameters,
    pk: int,
    unique_id: str,
) -> bool:
    """
    验证解密证明

    步骤：
    1. 重新计算挑战值
    2. 验证 a^f == a1 * d^c mod p
    3. 验证 g^f == b1 * h^c mod p
    """
    is_cipher(cipher)
    is_system_parameters(sp)

    a, b = cipher.a, cipher.b
    a1, b1, f, d = proof.a1, proof.b1, proof.f, proof.d

    c = _generate_challenge(sp.q, unique_id, a, b, a1, b1)

    # 验证 a^f == a1 * d^c mod p
    l1 = _pow(a, f, sp)
    r1 = _mul(a1, _pow(d, c, sp), sp)
    v1 = GlobalHelper.timing_safe_equal_bn(l1, r1)

    # 验证 g^f == b1 * h^c mod p
    l2 = _pow(sp.g, f, sp)
    r2 = _mul(b1, _pow(pk, c, sp), sp)
    v2 = GlobalHelper.timing_safe_equal_bn(l2, r2)

    return v1 and v2
