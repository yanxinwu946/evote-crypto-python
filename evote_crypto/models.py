"""全局数据模型定义"""

from dataclasses import dataclass


@dataclass
class Summary:
    """投票结果汇总"""
    total: int  # 总票数
    yes: int    # 赞成票数
    no: int     # 反对票数
