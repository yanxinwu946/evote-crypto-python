"""
有限域 ElGamal 零知识证明数据模型

对应原 TypeScript 项目中的 src/ff-elgamal/proofs/models.ts
"""

from dataclasses import dataclass


@dataclass
class KeyGenerationProof:
    """密钥生成证明（Schnorr 证明）"""
    c: int  # 挑战值
    d: int  # 响应值


@dataclass
class MembershipProof:
    """成员证明（析取 Chaum-Pedersen 证明）"""
    a0: int
    a1: int
    b0: int
    b1: int
    c0: int
    c1: int
    f0: int
    f1: int


@dataclass
class DecryptionProof:
    """解密证明（Chaum-Pedersen 证明）"""
    a1: int
    b1: int
    f: int
    d: int
