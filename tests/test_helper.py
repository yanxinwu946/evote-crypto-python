"""
全局辅助函数测试
"""

import pytest
from evote_crypto import helper


class TestBNOperations:
    """大数运算测试"""

    def test_new_bn(self):
        assert helper.new_bn(42) == 42
        assert helper.new_bn(0) == 0

    def test_add_bn(self):
        assert helper.add_bn(3, 4, 7) == 0  # (3+4) % 7 = 0
        assert helper.add_bn(3, 4, 10) == 7
        assert helper.add_bn(5, 5, 7) == 3  # (5+5) % 7 = 3

    def test_sub_bn(self):
        assert helper.sub_bn(3, 4, 7) == 6  # (3-4) % 7 = -1 % 7 = 6
        assert helper.sub_bn(4, 3, 7) == 1
        assert helper.sub_bn(10, 3, 7) == 0

    def test_mul_bn(self):
        assert helper.mul_bn(3, 4, 7) == 5  # (3*4) % 7 = 5
        assert helper.mul_bn(3, 4, 10) == 2  # (3*4) % 10 = 2

    def test_div_bn(self):
        # a / b mod p = a * b^(-1) mod p
        # 6 / 2 mod 7 = 6 * 4 mod 7 = 24 % 7 = 3
        assert helper.div_bn(6, 2, 7) == 3

    def test_pow_bn(self):
        assert helper.pow_bn(2, 3, 7) == 1  # 2^3 % 7 = 8 % 7 = 1
        assert helper.pow_bn(3, 2, 7) == 2  # 3^2 % 7 = 9 % 7 = 2

    def test_invm_bn(self):
        # 3 * 3^(-1) mod 7 = 1
        inv = helper.invm_bn(3, 7)
        assert (3 * inv) % 7 == 1


class TestSecureRandom:
    """安全随机数测试"""

    def test_random_in_range(self):
        n = 100
        for _ in range(10):
            r = helper.get_secure_random_value(n)
            assert 1 <= r <= n - 1

    def test_random_with_large_number(self):
        n = 2**256
        r = helper.get_secure_random_value(n)
        assert 1 <= r <= n - 1


class TestTimingSafeEqual:
    """时间安全比较测试"""

    def test_equal_bytes(self):
        assert helper.timing_safe_equal(b"hello", b"hello") is True

    def test_unequal_bytes(self):
        assert helper.timing_safe_equal(b"hello", b"world") is False

    def test_different_length(self):
        assert helper.timing_safe_equal(b"hi", b"hello") is False

    def test_equal_bn(self):
        assert helper.timing_safe_equal_bn(42, 42) is True

    def test_unequal_bn(self):
        assert helper.timing_safe_equal_bn(42, 43) is False

    def test_type_error(self):
        with pytest.raises(TypeError):
            helper.timing_safe_equal("not bytes", b"hello")
