"""
椭圆曲线 ElGamal 数据模型定义

对应原 TypeScript 项目中的 src/ec-elgamal/models.ts
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CurvePoint:
    """
    椭圆曲线上的点

    使用仿射坐标 (x, y) 表示。
    无穷远点用 x=None, y=None 表示。
    """
    x: Optional[int] = None
    y: Optional[int] = None

    def is_infinity(self) -> bool:
        """判断是否为无穷远点"""
        return self.x is None and self.y is None

    def __eq__(self, other) -> bool:
        if not isinstance(other, CurvePoint):
            return False
        return self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        return hash((self.x, self.y))

    def __repr__(self) -> str:
        if self.is_infinity():
            return "CurvePoint(无穷远点)"
        return f"CurvePoint({self.x}, {self.y})"


@dataclass
class SystemParameters:
    """椭圆曲线系统参数"""
    p: int          # 素数（曲线定义域）
    n: int          # 子群的阶
    g: CurvePoint   # 生成元


@dataclass
class KeyPair:
    """椭圆曲线密钥对"""
    h: CurvePoint   # 公钥 h = g * sk
    sk: int         # 私钥


@dataclass
class Cipher:
    """椭圆曲线密文"""
    a: CurvePoint           # a = g * r
    b: CurvePoint           # b = h * r + m
    r: Optional[int] = None  # 加密使用的随机数
