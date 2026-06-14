"""
椭圆曲线 ElGamal 投票测试
"""

from evote_crypto.ec_elgamal import SystemSetup, Encryption, Voting, Helper
from evote_crypto.ec_elgamal.curve import get_curve


class TestECVoting:
    """椭圆曲线投票流程测试"""

    def setup_method(self):
        self.kp = SystemSetup.generate_key_pair()
        self.curve = get_curve()

    def test_yes_vote(self):
        """测试赞成投票"""
        vote = Voting.generate_yes_vote(self.kp.h)
        assert self.curve.validate(vote.a)
        assert self.curve.validate(vote.b)

    def test_no_vote(self):
        """测试反对投票"""
        vote = Voting.generate_no_vote(self.kp.h)
        assert self.curve.validate(vote.a)
        assert self.curve.validate(vote.b)

    def test_find_point(self):
        """测试点查找"""
        # 0 = 无穷远点
        assert Voting.find_point(self.curve.point(None, None)) == 0
        # 1 = G
        assert Voting.find_point(self.curve.g) == 1
        # 2 = 2*G
        two_g = self.curve.add(self.curve.g, self.curve.g)
        assert Voting.find_point(two_g) == 2

    def test_tally_all_yes(self):
        """测试全部赞成的计票"""
        pk_hex = Helper.serialize_curve_point(self.kp.h)
        votes = [
            Voting.generate_yes_vote(self.kp.h),
            Voting.generate_yes_vote(self.kp.h),
        ]
        result = Voting.tally_votes(pk_hex, self.kp.sk, votes)
        assert result == 2

    def test_tally_all_no(self):
        """测试全部反对的计票"""
        pk_hex = Helper.serialize_curve_point(self.kp.h)
        votes = [
            Voting.generate_no_vote(self.kp.h),
            Voting.generate_no_vote(self.kp.h),
        ]
        result = Voting.tally_votes(pk_hex, self.kp.sk, votes)
        assert result == 0

    def test_tally_mixed(self):
        """测试混合投票计票"""
        pk_hex = Helper.serialize_curve_point(self.kp.h)
        votes = [
            Voting.generate_yes_vote(self.kp.h),
            Voting.generate_no_vote(self.kp.h),
            Voting.generate_yes_vote(self.kp.h),
        ]
        result = Voting.tally_votes(pk_hex, self.kp.sk, votes)
        assert result == 2

    def test_summary(self):
        """测试投票结果汇总"""
        summary = Voting.get_summary(total=5, tally_result=3)
        assert summary.total == 5
        assert summary.yes == 3
        assert summary.no == 2
