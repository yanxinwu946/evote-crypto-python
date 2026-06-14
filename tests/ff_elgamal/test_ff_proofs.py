"""
有限域 ElGamal 零知识证明测试
"""

from evote_crypto.ff_elgamal import SystemSetup, Encryption
from evote_crypto.ff_elgamal.proofs import KeyGeneration, Membership, Decryption


class TestKeyGenerationProof:
    """密钥生成证明测试（Schnorr 证明）"""

    def setup_method(self):
        # p=11, g=3 满足 g^q mod p == 1（q=5, 3^5 mod 11 = 1）
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys_zkp(p=11, g=3)

    def test_generate_and_verify(self):
        """测试生成和验证密钥证明"""
        proof = KeyGeneration.generate(self.sp, self.kp, "test-id")
        result = KeyGeneration.verify(self.sp, proof, self.kp.h, "test-id")
        assert result is True

    def test_verify_with_wrong_id(self):
        """测试使用错误 ID 验证"""
        proof = KeyGeneration.generate(self.sp, self.kp, "test-id")
        result = KeyGeneration.verify(self.sp, proof, self.kp.h, "wrong-id")
        assert result is False

    def test_verify_with_wrong_key(self):
        """测试使用错误公钥验证"""
        proof = KeyGeneration.generate(self.sp, self.kp, "test-id")
        other_kp = SystemSetup.generate_key_pair(self.sp)
        result = KeyGeneration.verify(self.sp, proof, other_kp.h, "test-id")
        assert result is False


class TestMembershipProof:
    """成员证明测试（析取 Chaum-Pedersen 证明）"""

    def setup_method(self):
        # p=11, g=3 满足 ZKP 要求
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys(p=11, g=3)

    def test_yes_proof(self):
        """测试赞成投票证明"""
        cipher = Encryption.encrypt(1, self.sp, self.kp.h, log=False)
        proof = Membership.generate_yes_proof(cipher, self.sp, self.kp.h, "vote-1")
        result = Membership.verify(cipher, proof, self.sp, self.kp.h, "vote-1")
        assert result is True

    def test_no_proof(self):
        """测试反对投票证明"""
        cipher = Encryption.encrypt(0, self.sp, self.kp.h, log=False)
        proof = Membership.generate_no_proof(cipher, self.sp, self.kp.h, "vote-2")
        result = Membership.verify(cipher, proof, self.sp, self.kp.h, "vote-2")
        assert result is True

    def test_yes_proof_with_wrong_id(self):
        """测试使用错误 ID 验证赞成投票证明"""
        cipher = Encryption.encrypt(1, self.sp, self.kp.h, log=False)
        proof = Membership.generate_yes_proof(cipher, self.sp, self.kp.h, "vote-1")
        result = Membership.verify(cipher, proof, self.sp, self.kp.h, "wrong-id")
        assert result is False


class TestDecryptionProof:
    """解密证明测试（Chaum-Pedersen 证明）"""

    def setup_method(self):
        # p=11, g=3 满足 ZKP 要求
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys(p=11, g=3)

    def test_generate_and_verify(self):
        """测试生成和验证解密证明"""
        cipher = Encryption.encrypt(1, self.sp, self.kp.h, log=False)
        proof = Decryption.generate(cipher, self.sp, self.kp.sk, "decrypt-1")
        result = Decryption.verify(
            cipher, proof, self.sp, self.kp.h, "decrypt-1"
        )
        assert result is True

    def test_verify_with_wrong_id(self):
        """测试使用错误 ID 验证解密证明"""
        cipher = Encryption.encrypt(1, self.sp, self.kp.h, log=False)
        proof = Decryption.generate(cipher, self.sp, self.kp.sk, "decrypt-1")
        result = Decryption.verify(
            cipher, proof, self.sp, self.kp.h, "wrong-id"
        )
        assert result is False
