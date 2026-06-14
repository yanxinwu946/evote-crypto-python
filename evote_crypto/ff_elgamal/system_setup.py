"""
有限域 ElGamal 系统设置

- 生成系统参数 p, q, g
- 生成密钥对 h, sk
- 合并公钥/私钥份额

对应原 TypeScript 项目中的 src/ff-elgamal/systemSetup.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.ff_elgamal.helper import get_q_of_p
from evote_crypto.ff_elgamal.models import (
    KeyPair,
    SystemParameters,
    is_system_parameters,
)


def generate_system_parameters(p: int, g: int) -> SystemParameters:
    """根据给定的 p 和 g 生成系统参数 p, q, g"""
    return SystemParameters(
        p=GlobalHelper.new_bn(p),
        q=GlobalHelper.new_bn(get_q_of_p(p)),
        g=GlobalHelper.new_bn(g),
    )


def generate_key_pair(sp: SystemParameters) -> KeyPair:
    """
    随机生成密钥对 h, sk

    给定系统参数 p, q, g：
    - 随机选择私钥 sk ∈ Z_q
    - 计算公钥 h = g^sk mod p
    """
    is_system_parameters(sp)
    sk = GlobalHelper.get_secure_random_value(sp.q)
    h = GlobalHelper.pow_bn(sp.g, sk, sp.p)
    return KeyPair(h=h, sk=sk)


def generate_system_parameters_and_keys(p: int, g: int) -> tuple:
    """生成系统参数和密钥对"""
    sys_params = generate_system_parameters(p, g)
    key_pair = generate_key_pair(sys_params)
    return sys_params, key_pair


def generate_system_parameters_and_keys_zkp(p: int, g: int) -> tuple:
    """
    生成适用于零知识证明的系统参数和密钥对

    额外验证：
    - g^q mod p == 1（即 gcd(q, p) == 1）
    - h^q mod p == 1（即 gcd(h, p) == 1）
    - 公钥 h 不等于 1
    """
    sys_params = generate_system_parameters(p, g)
    key_pair = generate_key_pair(sys_params)

    # 验证 g^q mod p == 1
    test1 = GlobalHelper.pow_bn(sys_params.g, sys_params.q, sys_params.p)
    if test1 != 1:
        raise ValueError(
            f"g^q mod p != 1 (== {test1}), "
            f"p: {p}, q: {sys_params.q}, g: {g}"
        )

    # 验证 h^q mod p == 1
    test2 = GlobalHelper.pow_bn(key_pair.h, sys_params.q, sys_params.p)
    if test2 != 1:
        raise ValueError(
            f"h^q mod p != 1 (== {test2}), "
            f"p: {p}, q: {sys_params.q}, g: {g}"
        )

    # 验证公钥 h 不等于 1
    test3 = key_pair.h % sys_params.p
    if test3 == 1:
        raise ValueError(f"h mod p == 1, p: {p}, q: {sys_params.q}, g: {g}")

    return sys_params, key_pair


def combine_public_keys(params: SystemParameters, public_key_shares: list) -> int:
    """
    合并多个公钥份额为一个公钥

    h = h_1 * h_2 * ... * h_n mod p
    """
    is_system_parameters(params)
    product = 1
    for share in public_key_shares:
        product = GlobalHelper.mul_bn(product, share, params.p)
    return product


def combine_private_keys(params: SystemParameters, private_key_shares: list) -> int:
    """
    合并多个私钥份额为一个私钥

    注意：这会使分布式私钥份额失效，仅用于测试目的。
    sk = sk_1 + sk_2 + ... + sk_n mod q
    """
    is_system_parameters(params)
    total = 0
    for share in private_key_shares:
        total = GlobalHelper.add_bn(total, share, params.q)
    return total
