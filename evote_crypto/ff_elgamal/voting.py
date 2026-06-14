"""
有限域 ElGamal 投票模块

- 生成赞成/反对投票
- 计票（累加并解密投票）
- 获取投票结果汇总

对应原 TypeScript 项目中的 src/ff-elgamal/voting.ts
"""

from evote_crypto import helper as GlobalHelper
from evote_crypto.models import Summary
from evote_crypto.ff_elgamal import encryption as Encryption
from evote_crypto.ff_elgamal.models import Cipher, SystemParameters


def generate_yes_vote(sp: SystemParameters, pk: int) -> Cipher:
    """生成赞成投票（加密 m=1）"""
    return Encryption.encrypt(1, sp, pk)


def generate_no_vote(sp: SystemParameters, pk: int) -> Cipher:
    """生成反对投票（加密 m=0）"""
    return Encryption.encrypt(0, sp, pk)


def generate_base_vote() -> Cipher:
    """
    生成基础投票（单位元）

    用 m=0, r=0 加密，即 (1, 1)
    """
    return Cipher(a=1, b=1)


def add_votes(votes: list, sp: SystemParameters) -> Cipher:
    """
    累加所有投票

    使用同态加法将所有加密投票相加。
    """
    result = generate_base_vote()
    for vote in votes:
        result = Encryption.add(result, vote, sp)
    return result


def tally_votes(sp: SystemParameters, sk: int, votes: list) -> int:
    """
    计票

    累加所有投票并解密得到赞成票总数。
    """
    return Encryption.decrypt1(add_votes(votes, sp), sk, sp)


def get_summary(total: int, tally_result: int) -> Summary:
    """
    获取投票结果汇总

    参数:
        total: 总投票数
        tally_result: 计票结果（赞成票数）

    返回:
        Summary 包含总票数、赞成票数和反对票数
    """
    yes = tally_result
    no = total - yes
    return Summary(total=total, yes=yes, no=no)
