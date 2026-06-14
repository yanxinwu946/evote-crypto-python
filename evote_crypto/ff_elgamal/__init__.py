"""
有限域 ElGamal 加密系统

基于有限域（素数域）实现 ElGamal 同态加密，
支持分布式密钥生成和零知识证明。
"""

from evote_crypto.ff_elgamal import encryption as Encryption
from evote_crypto.ff_elgamal import helper as Helper
from evote_crypto.ff_elgamal import proofs as Proof
from evote_crypto.ff_elgamal import system_setup as SystemSetup
from evote_crypto.ff_elgamal import voting as Voting

from evote_crypto.ff_elgamal.models import (
    Cipher,
    KeyPair,
    SystemParameters,
    is_cipher,
    is_key_pair,
    is_system_parameters,
)

__all__ = [
    "Encryption",
    "Helper",
    "Proof",
    "SystemSetup",
    "Voting",
    "Cipher",
    "KeyPair",
    "SystemParameters",
    "is_cipher",
    "is_key_pair",
    "is_system_parameters",
]
