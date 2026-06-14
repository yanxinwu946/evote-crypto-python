"""
椭圆曲线定义和操作

提供 Weierstrass 形式椭圆曲线上的点运算：
- 点加法
- 标量乘法
- 点取反
- 点验证

默认使用 secp256k1 曲线（也可自定义曲线参数）。
对应原 TypeScript 项目中的 src/ec-elgamal/curve.ts
"""

from typing import Optional
from evote_crypto.ec_elgamal.models import CurvePoint


class WeierstrassCurve:
    """
    Weierstrass 形式的椭圆曲线: y^2 = x^3 + a*x + b (mod p)

    提供椭圆曲线上的基本点运算。
    """

    def __init__(self, p: int, a: int, b: int, g: CurvePoint, n: int):
        """
        初始化椭圆曲线

        参数:
            p: 素数（有限域的模数）
            a: 曲线参数 a
            b: 曲线参数 b
            g: 生成元点
            n: 生成元的阶
        """
        self.p = p
        self.a = a
        self.b = b
        self.g = g
        self.n = n

    def validate(self, point: CurvePoint) -> bool:
        """
        验证点是否在曲线上

        检查 y^2 == x^3 + a*x + b (mod p)
        无穷远点始终有效。
        """
        if point.is_infinity():
            return True

        x, y = point.x, point.y
        if x is None or y is None:
            return False

        lhs = pow(y, 2, self.p)
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return lhs == rhs

    def point(self, x: Optional[int], y: Optional[int]) -> CurvePoint:
        """创建曲线上的点"""
        return CurvePoint(x=x, y=y)

    def add(self, p1: CurvePoint, p2: CurvePoint) -> CurvePoint:
        """
        椭圆曲线点加法

        规则：
        - O + P = P
        - P + O = P
        - P + (-P) = O
        - 其他情况使用标准加法公式
        """
        if p1.is_infinity():
            return p2
        if p2.is_infinity():
            return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        # P + (-P) = O
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return CurvePoint()  # 无穷远点

        if x1 == x2 and y1 == y2:
            # 点倍乘
            return self._double(p1)

        # 一般点加法
        lam = ((y2 - y1) * pow(x2 - x1, -1, self.p)) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return CurvePoint(x=x3, y=y3)

    def _double(self, point: CurvePoint) -> CurvePoint:
        """
        椭圆曲线点倍乘

        计算 2*P
        """
        if point.is_infinity():
            return point

        x, y = point.x, point.y

        # 切线斜率
        lam = ((3 * x * x + self.a) * pow(2 * y, -1, self.p)) % self.p
        x3 = (lam * lam - 2 * x) % self.p
        y3 = (lam * (x - x3) - y) % self.p

        return CurvePoint(x=x3, y=y3)

    def mul(self, point: CurvePoint, scalar: int) -> CurvePoint:
        """
        椭圆曲线标量乘法

        计算 scalar * P 使用 double-and-add 算法。
        """
        if scalar == 0 or point.is_infinity():
            return CurvePoint()  # 无穷远点

        if scalar < 0:
            # 负标量：取反点后用正标量
            point = self.neg(point)
            scalar = -scalar

        result = CurvePoint()  # 无穷远点（加法单位元）
        addend = point

        while scalar > 0:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1

        return result

    def neg(self, point: CurvePoint) -> CurvePoint:
        """
        椭圆曲线点取反

        -P = (x, -y mod p)
        """
        if point.is_infinity():
            return point
        return CurvePoint(x=point.x, y=(-point.y) % self.p)

    def sub(self, p1: CurvePoint, p2: CurvePoint) -> CurvePoint:
        """椭圆曲线点减法: P1 - P2 = P1 + (-P2)"""
        return self.add(p1, self.neg(p2))


# ============================================================
# 预定义曲线参数
# ============================================================

# secp256k1 曲线参数（比特币使用的曲线）
# y^2 = x^3 + 7 (mod p)
SECP256K1_P = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
)
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
)
SECP256K1_GY = (
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)
SECP256K1_N = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


def get_secp256k1_curve() -> WeierstrassCurve:
    """获取 secp256k1 曲线实例"""
    g = CurvePoint(x=SECP256K1_GX, y=SECP256K1_GY)
    return WeierstrassCurve(
        p=SECP256K1_P,
        a=SECP256K1_A,
        b=SECP256K1_B,
        g=g,
        n=SECP256K1_N,
    )


# 默认曲线实例（secp256k1）
_default_curve = None


def get_curve() -> WeierstrassCurve:
    """获取默认曲线实例（单例模式）"""
    global _default_curve
    if _default_curve is None:
        _default_curve = get_secp256k1_curve()
    return _default_curve


# 为了兼容性，导出曲线的常用属性
def _get_curve_attr(attr: str):
    """延迟获取曲线属性"""
    return getattr(get_curve(), attr)


class _CurveProxy:
    """
    曲线代理对象

    提供与原 TypeScript 代码兼容的接口。
    延迟初始化曲线实例。
    """

    @property
    def p(self) -> int:
        return get_curve().p

    @property
    def n(self) -> int:
        return get_curve().n

    @property
    def g(self) -> CurvePoint:
        return get_curve().g

    def validate(self, point: CurvePoint) -> bool:
        return get_curve().validate(point)

    def point(self, x: Optional[int], y: Optional[int]) -> CurvePoint:
        return get_curve().point(x, y)

    def mul(self, point: CurvePoint, scalar: int) -> CurvePoint:
        return get_curve().mul(point, scalar)

    def add(self, p1: CurvePoint, p2: CurvePoint) -> CurvePoint:
        return get_curve().add(p1, p2)

    def neg(self, point: CurvePoint) -> CurvePoint:
        return get_curve().neg(point)

    def sub(self, p1: CurvePoint, p2: CurvePoint) -> CurvePoint:
        return get_curve().sub(p1, p2)


# 导出的曲线接口
curve = _CurveProxy()
