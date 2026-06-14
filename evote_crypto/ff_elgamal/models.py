"""
有限域 ElGamal 数据模型定义

对应原 TypeScript 项目中的 src/ff-elgamal/models.ts
"""

from dataclasses import dataclass
from typing import Optional, Any


@dataclass
class SystemParameters:
    """系统参数"""
    p: int  # 素数 p
    q: int  # 素数因子 q: p = 2*q + 1
    g: int  # 群的生成元


def is_system_parameters(obj: Any) -> bool:
    """验证对象是否为有效的 SystemParameters 类型"""
    check1 = hasattr(obj, "p") and isinstance(obj.p, int)
    check2 = hasattr(obj, "q") and isinstance(obj.q, int)
    check3 = hasattr(obj, "g") and isinstance(obj.g, int)

    if not (check1 and check2 and check3):
        raise TypeError(
            f"提供的输入不是所需的 SystemParameters 类型。"
            f"给定: {obj}, 要求: {{p: int, q: int, g: int}}"
        )
    return True


@dataclass
class KeyPair:
    """密钥对"""
    h: int   # 公钥 h = g^sk mod p
    sk: int  # 私钥 sk: 0 < sk < q


def is_key_pair(obj: Any) -> bool:
    """验证对象是否为有效的 KeyPair 类型"""
    check1 = hasattr(obj, "h") and isinstance(obj.h, int)
    check2 = hasattr(obj, "sk") and isinstance(obj.sk, int)

    if not (check1 and check2):
        raise TypeError(
            f"提供的输入不是所需的 KeyPair 类型。"
            f"给定: {obj}, 要求: {{h: int, sk: int}}"
        )
    return True


@dataclass
class Cipher:
    """密文"""
    a: int              # a = g^r mod p
    b: int              # b = h^r * g^m mod p
    r: Optional[int] = None  # 加密使用的随机数


def is_cipher(obj: Any) -> bool:
    """验证对象是否为有效的 Cipher 类型"""
    check1 = hasattr(obj, "a") and isinstance(obj.a, int)
    check2 = hasattr(obj, "b") and isinstance(obj.b, int)
    r_present = hasattr(obj, "r") and obj.r is not None
    check3 = isinstance(obj.r, int) if r_present else True

    if not (check1 and check2):
        raise TypeError(
            f"提供的输入不是所需的 Cipher 类型。"
            f"给定: {obj}, 要求: {{a: int, b: int}}"
        )
    if r_present and not check3:
        raise TypeError(
            f"提供的输入不是所需的 Cipher 类型。"
            f"给定: {obj}, 要求: {{a: int, b: int, r?: int}}"
        )
    return check1 and check2 and check3
