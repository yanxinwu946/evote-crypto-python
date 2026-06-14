"""
有限域 ElGamal 加密测试
"""

from evote_crypto.ff_elgamal import SystemSetup, Encryption


class TestEncodeDecode:
    """消息编码/解码测试"""

    def setup_method(self):
        self.sp = SystemSetup.generate_system_parameters(p=11, g=2)

    def test_encode_decode_zero(self):
        encoded = Encryption.encode_message(0, self.sp)
        assert encoded == 1  # g^0 = 1

    def test_encode_decode_one(self):
        encoded = Encryption.encode_message(1, self.sp)
        assert encoded == 2  # g^1 = g = 2

    def test_encode_decode_roundtrip(self):
        for m in range(5):
            encoded = Encryption.encode_message(m, self.sp)
            decoded = Encryption.decode_message(encoded, self.sp)
            assert decoded == m


class TestEncryptDecrypt:
    """加密/解密测试"""

    def setup_method(self):
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys(p=11, g=2)

    def test_encrypt_decrypt_zero(self):
        cipher = Encryption.encrypt(0, self.sp, self.kp.h)
        plain = Encryption.decrypt1(cipher, self.kp.sk, self.sp)
        assert plain == 0

    def test_encrypt_decrypt_one(self):
        cipher = Encryption.encrypt(1, self.sp, self.kp.h)
        plain = Encryption.decrypt1(cipher, self.kp.sk, self.sp)
        assert plain == 1

    def test_decrypt2(self):
        cipher = Encryption.encrypt(1, self.sp, self.kp.h)
        plain = Encryption.decrypt2(cipher, self.kp.sk, self.sp)
        assert plain == 1

    def test_encrypt_decrypt_range(self):
        """测试整个消息范围"""
        for m in range(6):
            cipher = Encryption.encrypt(m, self.sp, self.kp.h)
            plain = Encryption.decrypt1(cipher, self.kp.sk, self.sp)
            assert plain == m


class TestHomomorphicAddition:
    """同态加法测试"""

    def setup_method(self):
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys(p=11, g=2)

    def test_add_two_ciphers(self):
        c1 = Encryption.encrypt(1, self.sp, self.kp.h)
        c2 = Encryption.encrypt(1, self.sp, self.kp.h)
        c_sum = Encryption.add(c1, c2, self.sp)
        plain = Encryption.decrypt1(c_sum, self.kp.sk, self.sp)
        assert plain == 2

    def test_add_multiple_ciphers(self):
        """测试多个密文的同态加法"""
        votes = [Encryption.encrypt(1, self.sp, self.kp.h) for _ in range(3)]
        c_sum = votes[0]
        for v in votes[1:]:
            c_sum = Encryption.add(c_sum, v, self.sp)
        plain = Encryption.decrypt1(c_sum, self.kp.sk, self.sp)
        assert plain == 3


class TestDistributedDecryption:
    """分布式解密测试"""

    def setup_method(self):
        self.sp = SystemSetup.generate_system_parameters(p=11, g=2)

    def test_decrypt_shares(self):
        """测试份额解密"""
        # 生成两个密钥对
        kp1 = SystemSetup.generate_key_pair(self.sp)
        kp2 = SystemSetup.generate_key_pair(self.sp)

        # 合并公钥
        combined_pk = SystemSetup.combine_public_keys(self.sp, [kp1.h, kp2.h])

        # 使用合并公钥加密
        cipher = Encryption.encrypt(1, self.sp, combined_pk)

        # 份额解密
        share1 = Encryption.decrypt_share(self.sp, cipher, kp1.sk)
        share2 = Encryption.decrypt_share(self.sp, cipher, kp2.sk)

        # 合并份额
        plain = Encryption.combine_decrypted_shares(self.sp, cipher, [share1, share2])
        assert plain == 1
