"""
哈希工具函数

提供与 web3.utils.soliditySha3 兼容的 Keccak-256 哈希函数。
注意：Keccak-256 不同于标准的 SHA3-256（NIST）。
"""

from Crypto.Hash import keccak


def keccak256(*args) -> int:
    """
    计算多个参数的 Keccak-256 哈希值

    模拟 web3.utils.soliditySha3 的行为：
    - 将每个参数序列化为字节串
    - 拼接后计算 Keccak-256 哈希
    - 返回哈希值的整数表示

    参数可以是 int、str 或 bytes 类型。
    """
    data = b""
    for arg in args:
        if isinstance(arg, int):
            # 将整数编码为 32 字节大端序（模拟 Solidity 的 uint256）
            data += arg.to_bytes(32, byteorder="big")
        elif isinstance(arg, str):
            # 字符串按 UTF-8 编码
            data += arg.encode("utf-8")
        elif isinstance(arg, (bytes, bytearray)):
            data += bytes(arg)
        else:
            data += str(arg).encode("utf-8")

    k = keccak.new(digest_bits=256)
    k.update(data)
    return int.from_bytes(k.digest(), byteorder="big")
