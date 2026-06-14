"""
椭圆曲线操作测试
"""

from evote_crypto.ec_elgamal.curve import get_curve, CurvePoint


class TestCurveOperations:
    """椭圆曲线基本操作测试"""

    def setup_method(self):
        self.curve = get_curve()

    def test_generator_on_curve(self):
        """测试生成元在曲线上"""
        assert self.curve.validate(self.curve.g) is True

    def test_point_at_infinity(self):
        """测试无穷远点"""
        inf = CurvePoint()
        assert inf.is_infinity() is True
        assert self.curve.validate(inf) is True

    def test_point_addition_identity(self):
        """测试加法单位元"""
        g = self.curve.g
        inf = CurvePoint()
        # P + O = P
        result = self.curve.add(g, inf)
        assert result.x == g.x and result.y == g.y
        # O + P = P
        result = self.curve.add(inf, g)
        assert result.x == g.x and result.y == g.y

    def test_point_negation(self):
        """测试点取反"""
        g = self.curve.g
        neg_g = self.curve.neg(g)
        # P + (-P) = O
        result = self.curve.add(g, neg_g)
        assert result.is_infinity()

    def test_point_doubling(self):
        """测试点倍乘"""
        g = self.curve.g
        two_g = self.curve.add(g, g)
        assert self.curve.validate(two_g)
        assert not two_g.is_infinity()

    def test_scalar_multiplication(self):
        """测试标量乘法"""
        g = self.curve.g
        # 1 * G = G
        result = self.curve.mul(g, 1)
        assert result.x == g.x and result.y == g.y
        # 2 * G = G + G
        result = self.curve.mul(g, 2)
        expected = self.curve.add(g, g)
        assert result.x == expected.x and result.y == expected.y

    def test_scalar_multiplication_zero(self):
        """测试零标量乘法"""
        g = self.curve.g
        result = self.curve.mul(g, 0)
        assert result.is_infinity()

    def test_curve_equation(self):
        """测试曲线方程 y^2 = x^3 + 7"""
        p = self.curve.p
        x = self.curve.g.x
        y = self.curve.g.y
        lhs = pow(y, 2, p)
        rhs = (pow(x, 3, p) + 7) % p
        assert lhs == rhs
