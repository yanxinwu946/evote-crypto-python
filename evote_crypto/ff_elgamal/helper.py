"""
有限域 ElGamal 辅助函数

提供素数检测、原根求解、安全素数候选等工具函数。
对应原 TypeScript 项目中的 src/ff-elgamal/helper.ts
"""

import math


def is_prime(num: int) -> bool:
    """检查给定数字是否为素数"""
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True


def get_primitive_roots(n: int) -> list:
    """
    获取给定素数的所有原根

    仅适用于素数。对于非素数返回空列表。
    """
    if not is_prime(n):
        return []

    g = []
    for i in range(1, n):
        exp = 1
        next_val = i % n

        while next_val != 1:
            next_val = (next_val * i) % n
            exp += 1

        if exp == n - 1:
            g.append(i)

    return g


def get_q_of_p(p: int) -> int:
    """
    根据 p 计算 q: q = (p-1)/2

    TODO: 可以检查 p 是否为素数
    """
    return (p - 1) // 2 if p > 1 else -1


def is_q_valid(q: int) -> bool:
    """q 有效当且仅当它是素数"""
    return is_prime(q) if q > 1 else False


def is_g_valid(g: int, p: int) -> bool:
    """
    g 有效的条件：
    - g != 1
    - g != q
    - g^q mod p == 1
    """
    q = get_q_of_p(p)
    return g != 1 and g != q and pow(g, q, p) == 1


def get_p_candidates(primes: list) -> list:
    """
    获取所有满足 q = (p-1)/2 也是素数的素数 p

    即安全素数候选。
    """
    return [p for p in primes if is_q_valid(get_q_of_p(p))]


def get_g_candidates(p: int) -> list:
    """获取给定素数 p 的所有生成元 g"""
    q = get_q_of_p(p)
    return [g for g in get_primitive_roots(q) if is_g_valid(g, p)]
