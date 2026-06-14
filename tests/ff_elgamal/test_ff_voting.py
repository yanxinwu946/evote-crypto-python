"""
有限域 ElGamal 投票测试
"""

from evote_crypto.ff_elgamal import SystemSetup, Voting


class TestVoting:
    """投票流程测试"""

    def setup_method(self):
        self.sp, self.kp = SystemSetup.generate_system_parameters_and_keys(p=11, g=2)

    def test_yes_vote(self):
        """测试赞成投票"""
        vote = Voting.generate_yes_vote(self.sp, self.kp.h)
        plain = Voting.tally_votes(self.sp, self.kp.sk, [vote])
        assert plain == 1

    def test_no_vote(self):
        """测试反对投票"""
        vote = Voting.generate_no_vote(self.sp, self.kp.h)
        plain = Voting.tally_votes(self.sp, self.kp.sk, [vote])
        assert plain == 0

    def test_multiple_votes(self):
        """测试多票计票"""
        votes = [
            Voting.generate_yes_vote(self.sp, self.kp.h),
            Voting.generate_yes_vote(self.sp, self.kp.h),
            Voting.generate_no_vote(self.sp, self.kp.h),
        ]
        tally = Voting.tally_votes(self.sp, self.kp.sk, votes)
        assert tally == 2  # 2 票赞成

    def test_summary(self):
        """测试投票结果汇总"""
        summary = Voting.get_summary(total=10, tally_result=7)
        assert summary.total == 10
        assert summary.yes == 7
        assert summary.no == 3

    def test_distributed_voting(self):
        """测试分布式投票"""
        # 生成两个参与者
        kp1 = SystemSetup.generate_key_pair(self.sp)
        kp2 = SystemSetup.generate_key_pair(self.sp)

        # 合并公钥
        combined_pk = SystemSetup.combine_public_keys(self.sp, [kp1.h, kp2.h])

        # 投票
        votes = [
            Voting.generate_yes_vote(self.sp, combined_pk),
            Voting.generate_no_vote(self.sp, combined_pk),
            Voting.generate_yes_vote(self.sp, combined_pk),
        ]

        # 累加投票
        vote_sum = Voting.add_votes(votes, self.sp)

        # 份额解密
        from evote_crypto.ff_elgamal import Encryption
        share1 = Encryption.decrypt_share(self.sp, vote_sum, kp1.sk)
        share2 = Encryption.decrypt_share(self.sp, vote_sum, kp2.sk)

        # 合并份额
        plain = Encryption.combine_decrypted_shares(
            self.sp, vote_sum, [share1, share2]
        )
        assert plain == 2  # 2 票赞成
