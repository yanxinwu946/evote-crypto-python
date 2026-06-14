"""
椭圆曲线 ElGamal 辅助函数

提供椭圆曲线点运算的便捷函数、序列化/反序列化等工具。
对应原 TypeScript 项目中的 src/ec-elgamal/helper.ts
"""

from evote_crypto.ec_elgamal.models import CurvePoint, SystemParameters
from evote_crypto.ec_elgamal.curve import get_curve


def ec_pow(a: CurvePoint, b: int) -> CurvePoint:
    """椭圆曲线标量乘法: a * b（即 b 个 a 相加）"""
    return get_curve().mul(a, b)


def ec_mul(a: CurvePoint, b: CurvePoint) -> CurvePoint:
    """椭圆曲线点加法: a + b"""
    return get_curve().add(a, b)


def ec_div(a: CurvePoint, b: CurvePoint) -> CurvePoint:
    """椭圆曲线点减法: a - b = a + (-b)"""
    return get_curve().sub(a, b)


def curve_point_to_string(point: CurvePoint) -> str:
    """将曲线点转换为十六进制字符串"""
    if point.is_infinity():
        return "infinity"
    px = format(point.x, '064x')
    py = format(point.y, '064x')
    return px + py


def curve_points_to_string(points: list) -> str:
    """将多个曲线点转换为十六进制字符串"""
    return "".join(curve_point_to_string(p) for p in points)


def serialize_bn(bn: int) -> str:
    """将大数序列化为十六进制字符串"""
    return format(bn, 'x')


def deserialize_bn(bn: str) -> int:
    """将十六进制字符串反序列化为大数"""
    return int(bn, 16)


def serialize_curve_point(point: CurvePoint) -> str:
    """将曲线点序列化为未压缩格式的十六进制字符串"""
    if point.is_infinity():
        return "00"
    # 未压缩格式: 04 + x + y
    x_hex = format(point.x, '064x')
    y_hex = format(point.y, '064x')
    return "04" + x_hex + y_hex


def deserialize_curve_point(point) -> CurvePoint:
    """
    将曲线点从十六进制字符串或 CurvePoint 对象反序列化

    如果输入已经是 CurvePoint 对象，直接返回。
    """
    if isinstance(point, CurvePoint):
        return point

    if not isinstance(point, str):
        raise TypeError(f"无法反序列化类型: {type(point)}")

    if point == "00":
        return CurvePoint()  # 无穷远点

    # 去掉未压缩格式前缀
    if point.startswith("04"):
        point = point[2:]

    x = int(point[:64], 16)
    y = int(point[64:], 16)
    return CurvePoint(x=x, y=y)


def serialize_system_parameters(params: SystemParameters) -> dict:
    """将系统参数序列化为字典"""
    return {
        "p": serialize_bn(params.p),
        "n": serialize_bn(params.n),
        "g": serialize_curve_point(params.g),
    }


def deserialize_params(params) -> SystemParameters:
    """
    将系统参数从字典或 SystemParameters 对象反序列化

    如果输入已经是 SystemParameters 对象，直接返回。
    """
    if isinstance(params, SystemParameters):
        return params

    if isinstance(params, dict):
        return SystemParameters(
            p=deserialize_bn(params["p"]),
            n=deserialize_bn(params["n"]),
            g=deserialize_curve_point(params["g"]),
        )

    raise TypeError(f"无法反序列化类型: {type(params)}")
