"""
椭圆曲线 ElGamal 加密

- 消息加密和解密
- 同态加法
- 份额解密和合并

对应原 TypeScript 项目中的 src/ec-elgamal/encryption.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.ec_elgamal.curve import get_curve
from evote_crypto.ec_elgamal.helper import ec_mul, ec_div, ec_pow
from evote_crypto.ec_elgamal.models import Cipher, CurvePoint


def encrypt(message: CurvePoint, public_key: CurvePoint, log: bool = False) -> Cipher:
    """
    椭圆曲线 ElGamal 加密

    给定：
    - g: 生成元
    - h: 公钥 (g * privateKey)
    - m: 消息（曲线上的点）

    步骤：
    1. 选择随机值 r
    2. 计算 c1 = g * r（标量乘法）
    3. 计算 s = h * r（标量乘法）
    4. 计算 c2 = s + m（点加法）
    """
    curve = get_curve()
    r = GlobalHelper.get_secure_random_value(curve.n)

    c1 = curve.mul(curve.g, r)
    s = curve.mul(public_key, r)
    c2 = curve.add(s, message)

    if log:
        print(f"c1 在曲线上?\t{curve.validate(c1)}")
        print(f"s 在曲线上?\t{curve.validate(s)}")
        print(f"c2 在曲线上?\t{curve.validate(c2)}")

    return Cipher(a=c1, b=c2, r=r)


def decrypt(cipher_text: Cipher, private_key: int, log: bool = False) -> CurvePoint:
    """
    椭圆曲线 ElGamal 解密

    步骤：
    1. 计算 s = c1 * sk（标量乘法）
    2. 计算 s^(-1) = -s（点取反）
    3. 计算 m = c2 + s^(-1)（点加法）
    """
    curve = get_curve()
    c1, c2 = cipher_text.a, cipher_text.b

    s = curve.mul(c1, private_key)
    s_inverse = curve.neg(s)
    m = curve.add(c2, s_inverse)

    if log:
        print(f"s 在曲线上?\t{curve.validate(s)}")
        print(f"s^(-1) 在曲线上?\t{curve.validate(s_inverse)}")
        print(f"m 在曲线上?\t{curve.validate(m)}")

    return m


def homomorphic_add(cipher0: Cipher, cipher1: Cipher) -> Cipher:
    """
    同态加法

    E(m1) + E(m2) = (a1 + a2, b1 + b2)
    """
    curve = get_curve()
    return Cipher(
        a=curve.add(cipher0.a, cipher1.a),
        b=curve.add(cipher0.b, cipher1.b),
    )


def decrypt_share(cipher: Cipher, secret_key_share: int) -> CurvePoint:
    """
    使用私钥份额解密密文

    d_i = a * sk_i
    """
    return ec_pow(cipher.a, secret_key_share)


def combine_decrypted_shares(
    cipher: Cipher,
    decrypted_shares: list,
) -> CurvePoint:
    """
    合并解密份额得到明文

    m = b - (d_1 + d_2 + ... + d_n)
    """
    product = CurvePoint()  # 无穷远点
    for share in decrypted_shares:
        product = ec_mul(product, share)

    return ec_div(cipher.b, product)
