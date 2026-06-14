"""
椭圆曲线 ElGamal 零知识证明模块

包含：
- 密钥生成证明（Schnorr 证明）
- 解密证明（Chaum-Pedersen 证明）
- 成员证明（析取 Chaum-Pedersen 证明）
"""

from evote_crypto.ec_elgamal.proofs import decryption as Decryption
from evote_crypto.ec_elgamal.proofs import key_generation as KeyGeneration
from evote_crypto.ec_elgamal.proofs import membership as Membership
from evote_crypto.ec_elgamal.proofs.models import (
    DecryptionProof,
    KeyGenerationProof,
    MembershipProof,
)

__all__ = [
    "Decryption",
    "KeyGeneration",
    "Membership",
    "DecryptionProof",
    "KeyGenerationProof",
    "MembershipProof",
]
