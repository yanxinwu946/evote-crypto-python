"""
有限域 ElGamal 加密

- 消息编码和解码
- 消息加密和解密
- 同态加法
- 份额解密和合并

对应原 TypeScript 项目中的 src/ff-elgamal/encryption.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.ff_elgamal.models import (
    Cipher,
    SystemParameters,
    is_cipher,
    is_system_parameters,
)


def encode_message(m: int, sys_params: SystemParameters) -> int:
    """
    编码消息 m 为 g^m mod p

    这是实现同态加密的关键步骤。
    """
    is_system_parameters(sys_params)
    return GlobalHelper.pow_bn(sys_params.g, m, sys_params.p)


def decode_message(mh: int, sys_params: SystemParameters) -> int:
    """
    解码消息 g^m 为 m（暴力搜索）

    TODO: 使用 baby-step giant-step 算法替代暴力搜索
    """
    is_system_parameters(sys_params)
    m = 0
    while not GlobalHelper.timing_safe_equal_bn(encode_message(m, sys_params), mh):
        m += 1
    return m


def encrypt(
    message: int,
    sys_params: SystemParameters,
    public_key: int,
    log: bool = False,
) -> Cipher:
    """
    有限域 ElGamal 加密

    给定：
    - p: 素数
    - g: 生成元
    - h: 公钥 (g^privateKey)
    - m: 消息

    步骤：
    1. 选择随机值 r: 0 < r < q
    2. 计算 c1 = g^r mod p
    3. 计算 s = h^r mod p
    4. 编码消息 mh = g^m mod p（使其具有同态性）
    5. 计算 c2 = s * mh mod p
    """
    is_system_parameters(sys_params)

    r = GlobalHelper.get_secure_random_value(sys_params.q)
    c1 = GlobalHelper.pow_bn(sys_params.g, r, sys_params.p)
    s = GlobalHelper.pow_bn(public_key, r, sys_params.p)
    mh = encode_message(message, sys_params)
    c2 = GlobalHelper.mul_bn(s, mh, sys_params.p)

    if log:
        print(f"加密随机数 (r)\t{r}")
        print(f"a\t\t{c1}")
        print(f"h^r\t\t{s}")
        print(f"g^m\t\t{mh}")
        print(f"b\t\t{c2}")
        print("------------------------")

    return Cipher(a=c1, b=c2, r=r)


def decrypt1(
    cipher_text: Cipher,
    sk: int,
    sys_params: SystemParameters,
    log: bool = False,
) -> int:
    """
    有限域 ElGamal 解密（方法一：使用模逆元）

    步骤：
    1. 计算 s = c1^sk mod p
    2. 计算 s^(-1)（s 的乘法逆元）
    3. 计算 mh = c2 * s^(-1) mod p
    4. 暴力解码 mh 得到明文 m
    """
    is_cipher(cipher_text)
    is_system_parameters(sys_params)

    a, b = cipher_text.a, cipher_text.b

    s = GlobalHelper.pow_bn(a, sk, sys_params.p)
    s_inverse = GlobalHelper.invm_bn(s, sys_params.p)
    mh = GlobalHelper.mul_bn(b, s_inverse, sys_params.p)
    m = decode_message(mh, sys_params)

    if log:
        print(f"s\t\t{s}")
        print(f"s^(-1)\t\t{s_inverse}")
        print(f"mh\t\t{mh}")
        print(f"明文 d1\t\t{m}")
        print("------------------------")

    return m


def decrypt2(
    cipher_text: Cipher,
    sk: int,
    sys_params: SystemParameters,
    log: bool = False,
) -> int:
    """
    有限域 ElGamal 解密（方法二：使用欧拉定理）

    步骤：
    1. 计算 s = c1^sk mod p
    2. 计算 s^(p-2) mod p
    3. 计算 mh = c2 * s^(p-2) mod p
    4. 暴力解码 mh 得到明文 m
    """
    is_cipher(cipher_text)
    is_system_parameters(sys_params)

    a, b = cipher_text.a, cipher_text.b

    s = GlobalHelper.pow_bn(a, sk, sys_params.p)
    s_pow_p_minus_2 = GlobalHelper.pow_bn(s, sys_params.p - 2, sys_params.p)
    mh = GlobalHelper.mul_bn(b, s_pow_p_minus_2, sys_params.p)
    m = decode_message(mh, sys_params)

    if log:
        print(f"s\t\t{s}")
        print(f"s^(p-2)\t\t{s_pow_p_minus_2}")
        print(f"mh\t\t{mh}")
        print(f"明文 d2\t\t{m}")
        print("------------------------")

    return m


def add(em1: Cipher, em2: Cipher, sys_params: SystemParameters) -> Cipher:
    """
    同态加法

    E(m1) * E(m2) = (g^(r1+r2), h^(r1+r2) * g^(m1+m2)) = E(m1 + m2)
    """
    is_cipher(em1)
    is_cipher(em2)
    is_system_parameters(sys_params)
    return Cipher(
        a=GlobalHelper.mul_bn(em1.a, em2.a, sys_params.p),
        b=GlobalHelper.mul_bn(em1.b, em2.b, sys_params.p),
    )


def decrypt_share(params: SystemParameters, cipher: Cipher, secret_key_share: int) -> int:
    """
    使用私钥份额解密密文

    d_i = a^sk_i mod p
    """
    is_system_parameters(params)
    is_cipher(cipher)
    return GlobalHelper.pow_bn(cipher.a, secret_key_share, params.p)


def combine_decrypted_shares(
    params: SystemParameters,
    cipher: Cipher,
    decrypted_shares: list,
) -> int:
    """
    合并解密份额得到明文

    m = b / (d_1 * d_2 * ... * d_n) mod p
    """
    is_system_parameters(params)
    is_cipher(cipher)

    product = 1
    for share in decrypted_shares:
        product = GlobalHelper.mul_bn(product, share, params.p)

    mh = GlobalHelper.div_bn(cipher.b, product, params.p)
    return decode_message(mh, params)
