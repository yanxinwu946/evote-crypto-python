"""
有限域 ElGamal 辅助函数测试
"""

from evote_crypto.ff_elgamal import helper


class TestPrime:
    """素数检测测试"""

    def test_is_prime(self):
        assert helper.is_prime(2) is True
        assert helper.is_prime(3) is True
        assert helper.is_prime(5) is True
        assert helper.is_prime(7) is True
        assert helper.is_prime(11) is True

    def test_not_prime(self):
        assert helper.is_prime(0) is False
        assert helper.is_prime(1) is False
        assert helper.is_prime(4) is False
        assert helper.is_prime(6) is False
        assert helper.is_prime(9) is False


class TestPrimitiveRoots:
    """原根测试"""

    def test_primitive_roots_of_5(self):
        roots = helper.get_primitive_roots(5)
        assert 2 in roots
        assert 3 in roots

    def test_primitive_roots_of_non_prime(self):
        assert helper.get_primitive_roots(4) == []


class TestQOfP:
    """q = (p-1)/2 计算测试"""

    def test_valid_p(self):
        assert helper.get_q_of_p(7) == 3
        assert helper.get_q_of_p(11) == 5
        assert helper.get_q_of_p(23) == 11

    def test_invalid_p(self):
        assert helper.get_q_of_p(1) == -1
        assert helper.get_q_of_p(0) == -1


class TestCandidates:
    """候选值测试"""

    def test_p_candidates(self):
        primes = [3, 5, 7, 11, 13, 23]
        candidates = helper.get_p_candidates(primes)
        # p=7 -> q=3 (素数), p=11 -> q=5 (素数), p=23 -> q=11 (素数)
        assert 7 in candidates
        assert 11 in candidates
        assert 23 in candidates

    def test_g_candidates(self):
        # 对于 p=7, q=3, g 的候选应该是满足 g^3 mod 7 == 1 的值
        candidates = helper.get_g_candidates(7)
        for g in candidates:
            assert pow(g, 3, 7) == 1
            assert g != 1
