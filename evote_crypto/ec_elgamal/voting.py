"""
椭圆曲线 ElGamal 投票模块

- 生成赞成/反对投票
- 计票（累加并解密投票）
- 获取投票结果汇总

对应原 TypeScript 项目中的 src/ec-elgamal/voting.ts
"""

from evote_crypto.models import Summary
from evote_crypto.ec_elgamal import encryption as Encryption
from evote_crypto.ec_elgamal import helper as Helper
from evote_crypto.ec_elgamal.curve import get_curve
from evote_crypto.ec_elgamal.models import Cipher, CurvePoint


# 赞成票 = 生成元 g（代表 1）
# 反对票 = 无穷远点（代表 0）


def generate_yes_vote(pk) -> Cipher:
    """
    生成赞成投票

    使用生成元 g 作为消息（代表 1）。
    pk 可以是 CurvePoint 对象或十六进制字符串。
    """
    curve = get_curve()
    public_key = Helper.deserialize_curve_point(pk)
    return Encryption.encrypt(curve.g, public_key)


def generate_no_vote(pk) -> Cipher:
    """
    生成反对投票

    使用无穷远点作为消息（代表 0）。
    pk 可以是 CurvePoint 对象或十六进制字符串。
    """
    no_vote = CurvePoint()  # 无穷远点
    public_key = Helper.deserialize_curve_point(pk)
    return Encryption.encrypt(no_vote, public_key)


def generate_base_vote(pk) -> Cipher:
    """
    生成基础投票（用于同态加法的初始值）

    使用 m=无穷远点, r=1 加密：(g, pk)
    pk 可以是 CurvePoint 对象或十六进制字符串。
    """
    curve = get_curve()
    public_key = Helper.deserialize_curve_point(pk)
    return Cipher(a=curve.g, b=public_key)


def add_votes(votes: list, pk) -> Cipher:
    """
    累加所有投票

    使用同态加法将所有加密投票相加。
    pk 可以是 CurvePoint 对象或十六进制字符串。
    """
    public_key = Helper.deserialize_curve_point(pk)
    result = generate_base_vote(public_key)
    for vote in votes:
        result = Encryption.homomorphic_add(result, vote)
    return result


def find_point(point: CurvePoint) -> int:
    """
    通过暴力搜索找到点对应的计数值

    从无穷远点开始，不断加上生成元 g，
    直到找到与目标点匹配的计数值。
    """
    curve = get_curve()
    no_vote = CurvePoint()  # 无穷远点
    sum_point = no_vote
    counter = 0

    while not (sum_point.x == point.x and sum_point.y == point.y):
        sum_point = curve.add(sum_point, curve.g)
        counter += 1
        # 安全检查：防止无限循环
        if counter > curve.n:
            raise ValueError("无法找到对应的点计数值")

    return counter


def tally_votes(pk: str, sk: int, votes: list) -> int:
    """
    计票

    累加所有投票并解密，然后查找对应的计数值。

    参数:
        pk: 公钥（十六进制字符串）
        sk: 私钥
        votes: 加密投票列表
    """
    public_key = Helper.deserialize_curve_point(pk)
    vote_sum = add_votes(votes, public_key)
    decrypted_sum = Encryption.decrypt(vote_sum, sk)
    return find_point(decrypted_sum)


def get_summary(total: int, tally_result: int) -> Summary:
    """
    获取投票结果汇总

    参数:
        total: 总投票数
        tally_result: 计票结果（赞成票数）
    """
    yes = tally_result
    no = total - yes
    return Summary(total=total, yes=yes, no=no)
