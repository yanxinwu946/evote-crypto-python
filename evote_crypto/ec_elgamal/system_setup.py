"""
椭圆曲线 ElGamal 系统设置

- 生成系统参数
- 生成密钥对
- 合并公钥/私钥份额

对应原 TypeScript 项目中的 src/ec-elgamal/systemSetup.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.ec_elgamal.curve import get_curve
from evote_crypto.ec_elgamal.helper import ec_mul
from evote_crypto.ec_elgamal.models import (
    CurvePoint,
    KeyPair,
    SystemParameters,
)


def generate_system_parameters() -> SystemParameters:
    """生成椭圆曲线系统参数"""
    curve = get_curve()
    return SystemParameters(p=curve.p, n=curve.n, g=curve.g)


def generate_key_pair() -> KeyPair:
    """
    随机生成椭圆曲线密钥对

    - 随机选择私钥 sk ∈ Z_n
    - 计算公钥 h = g * sk（标量乘法）
    """
    curve = get_curve()
    sk = GlobalHelper.get_secure_random_value(curve.n)
    h = curve.mul(curve.g, sk)
    return KeyPair(h=h, sk=sk)


def combine_public_keys(public_key_shares: list) -> CurvePoint:
    """
    合并多个公钥份额为一个公钥

    h = h_1 + h_2 + ... + h_n（点加法）
    """
    result = CurvePoint()  # 无穷远点
    for share in public_key_shares:
        result = ec_mul(result, share)
    return result


def combine_private_keys(params: SystemParameters, private_key_shares: list) -> int:
    """
    合并多个私钥份额为一个私钥

    注意：这会使分布式私钥份额失效，仅用于测试目的。
    sk = sk_1 + sk_2 + ... + sk_n mod n
    """
    total = 0
    for share in private_key_shares:
        total = GlobalHelper.add_bn(total, share, params.n)
    return total
