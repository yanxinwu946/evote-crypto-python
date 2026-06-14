"""
椭圆曲线 ElGamal 加密系统

基于椭圆曲线实现 ElGamal 同态加密，
支持分布式密钥生成和零知识证明。
"""

from evote_crypto.ec_elgamal import curve as Curve
from evote_crypto.ec_elgamal import encryption as Encryption
from evote_crypto.ec_elgamal import helper as Helper
from evote_crypto.ec_elgamal import proofs as Proof
from evote_crypto.ec_elgamal import system_setup as SystemSetup
from evote_crypto.ec_elgamal import voting as Voting

from evote_crypto.ec_elgamal.models import Cipher, CurvePoint, KeyPair, SystemParameters

__all__ = [
    "Curve",
    "Encryption",
    "Helper",
    "Proof",
    "SystemSetup",
    "Voting",
    "Cipher",
    "CurvePoint",
    "KeyPair",
    "SystemParameters",
]
