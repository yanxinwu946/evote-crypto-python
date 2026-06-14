"""
椭圆曲线 ElGamal 加密测试
"""

from evote_crypto.ec_elgamal import SystemSetup, Encryption, Helper
from evote_crypto.ec_elgamal.curve import get_curve


class TestECEncryptDecrypt:
    """椭圆曲线加密/解密测试"""

    def setup_method(self):
        self.kp = SystemSetup.generate_key_pair()
        self.curve = get_curve()

    def test_encrypt_decrypt(self):
        """测试加密和解密"""
        message = self.curve.g
        cipher = Encryption.encrypt(message, self.kp.h)
        decrypted = Encryption.decrypt(cipher, self.kp.sk)
        assert decrypted.x == message.x and decrypted.y == message.y

    def test_encrypt_decrypt_infinity(self):
        """测试加密和解密无穷远点"""
        message = self.curve.point(None, None)
        cipher = Encryption.encrypt(message, self.kp.h)
        decrypted = Encryption.decrypt(cipher, self.kp.sk)
        assert decrypted.is_infinity()


class TestECHomomorphicAddition:
    """椭圆曲线同态加法测试"""

    def setup_method(self):
        self.kp = SystemSetup.generate_key_pair()
        self.curve = get_curve()

    def test_homomorphic_add(self):
        """测试同态加法"""
        m1 = self.curve.g
        m2 = self.curve.g

        c1 = Encryption.encrypt(m1, self.kp.h)
        c2 = Encryption.encrypt(m2, self.kp.h)

        c_sum = Encryption.homomorphic_add(c1, c2)
        decrypted = Encryption.decrypt(c_sum, self.kp.sk)

        # m1 + m2 = 2*G
        expected = self.curve.add(m1, m2)
        assert decrypted.x == expected.x and decrypted.y == expected.y


class TestECDistributedDecryption:
    """椭圆曲线分布式解密测试"""

    def test_decrypt_shares(self):
        """测试份额解密"""
        kp1 = SystemSetup.generate_key_pair()
        kp2 = SystemSetup.generate_key_pair()

        # 合并公钥
        combined_pk = SystemSetup.combine_public_keys([kp1.h, kp2.h])

        # 加密
        curve = get_curve()
        message = curve.g
        cipher = Encryption.encrypt(message, combined_pk)

        # 份额解密
        share1 = Encryption.decrypt_share(cipher, kp1.sk)
        share2 = Encryption.decrypt_share(cipher, kp2.sk)

        # 合并份额
        decrypted = Encryption.combine_decrypted_shares(cipher, [share1, share2])
        assert decrypted.x == message.x and decrypted.y == message.y
