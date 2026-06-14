"""
全局辅助函数

提供大数运算、安全随机数生成和时间安全比较等工具函数。
对应原 TypeScript 项目中的 src/helper.ts
"""

import os
import secrets


def new_bn(n: int) -> int:
    """创建大数（Python 原生 int 已支持任意精度）"""
    return int(n)


def invm_bn(a: int, modulus: int) -> int:
    """计算模逆元: a^(-1) mod modulus"""
    return pow(a, -1, modulus)


def add_bn(a: int, b: int, modulus: int) -> int:
    """模加法: (a + b) mod modulus"""
    return (a + b) % modulus


def sub_bn(a: int, b: int, modulus: int) -> int:
    """模减法: (a - b) mod modulus"""
    return (a - b) % modulus


def mul_bn(a: int, b: int, modulus: int) -> int:
    """模乘法: (a * b) mod modulus"""
    return (a * b) % modulus


def div_bn(a: int, b: int, modulus: int) -> int:
    """模除法: (a / b) mod modulus = a * b^(-1) mod modulus"""
    return mul_bn(a, invm_bn(b, modulus), modulus)


def pow_bn(a: int, b: int, modulus: int) -> int:
    """模幂运算: a^b mod modulus"""
    return pow(a, b, modulus)


def get_byte_size_for_decimal_number(n: int) -> int:
    """计算存储一个十进制数所需的字节数"""
    modulus = n % 256
    smaller_half = modulus < 128
    result = n // 256
    return result + 1 if smaller_half else result


def get_secure_random_value(n: int) -> int:
    """
    获取安全随机值 x，满足 0 < x < n

    使用 Python 的 secrets 模块生成密码学安全的随机数。
    """
    one = 1
    upper_bound = n - one
    byte_size = get_byte_size_for_decimal_number(n)

    # 对于非常大的数，使用 32 字节
    if byte_size > 1024:
        byte_size = 32

    while True:
        random_bytes = os.urandom(byte_size)
        random_value = int.from_bytes(random_bytes, byteorder="big")
        if one <= random_value <= upper_bound:
            return random_value


def timing_safe_equal(a: bytes, b: bytes) -> bool:
    """
    时间安全的字节串比较

    确保比较操作的执行时间不依赖于输入内容，
    防止时序攻击。
    """
    if not isinstance(a, (bytes, bytearray)):
        raise TypeError("第一个参数必须是 bytes 类型")
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("第二个参数必须是 bytes 类型")

    # 如果长度不同，不泄露信息，仍然进行完整比较
    mismatch = 0 if len(a) == len(b) else 1
    if mismatch:
        b = a

    for x, y in zip(a, b):
        mismatch |= x ^ y

    return mismatch == 0


def timing_safe_equal_bn(a: int, b: int) -> bool:
    """
    时间安全的大数比较

    将大数转换为字节串后进行时间安全比较。
    """
    if not isinstance(a, int):
        raise TypeError("第一个参数必须是 int 类型")
    if not isinstance(b, int):
        raise TypeError("第二个参数必须是 int 类型")

    # 转换为字节串，确保使用相同的字节长度
    max_val = max(a, b)
    byte_length = (max_val.bit_length() + 7) // 8
    byte_length = max(byte_length, 1)

    a_bytes = a.to_bytes(byte_length, byteorder="big")
    b_bytes = b.to_bytes(byte_length, byteorder="big")

    return timing_safe_equal(a_bytes, b_bytes)
