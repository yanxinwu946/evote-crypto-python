"""
电子投票密码学可视化 — Flask 后端

提供 REST API 接口，封装 evote_crypto 库的核心功能。
"""

from flask import Flask, render_template, jsonify, request
from evote_crypto.ff_elgamal import (
    SystemSetup as FFSetup,
    Encryption as FFEnc,
    Voting as FFVoting,
)
from evote_crypto.ff_elgamal.proofs import (
    KeyGeneration as FFKeyGenProof,
    Membership as FFMembershipProof,
    Decryption as FFDecProof,
)
from evote_crypto.ec_elgamal import (
    SystemSetup as ECSetup,
    Encryption as ECEnc,
    Voting as ECVoting,
    Helper as ECHelper,
)
from evote_crypto.ec_elgamal.curve import get_curve

app = Flask(__name__)

# ============================================================
# 页面路由
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# 有限域 ElGamal API
# ============================================================

@app.route("/api/ff/setup", methods=["POST"])
def ff_setup():
    """生成有限域系统参数和密钥对"""
    data = request.json or {}
    p = data.get("p", 23)
    g = data.get("g", 5)
    try:
        sp, kp = FFSetup.generate_system_parameters_and_keys_zkp(p, g)
        return jsonify({
            "success": True,
            "params": {"p": sp.p, "q": sp.q, "g": sp.g},
            "keypair": {"h": kp.h, "sk": kp.sk},
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/ff/encrypt", methods=["POST"])
def ff_encrypt():
    """有限域加密"""
    data = request.json
    msg = data["message"]
    p, g, pk = data["p"], data["g"], data["public_key"]
    sp = FFSetup.generate_system_parameters(p, g)
    cipher = FFEnc.encrypt(msg, sp, pk)
    return jsonify({
        "success": True,
        "cipher": {"a": cipher.a, "b": cipher.b, "r": cipher.r},
        "steps": _ff_encrypt_steps(msg, sp, pk, cipher),
    })


def _ff_encrypt_steps(msg, sp, pk, cipher):
    """记录加密的每一步"""
    r = cipher.r
    import evote_crypto.helper as H
    c1 = H.pow_bn(sp.g, r, sp.p)
    s = H.pow_bn(pk, r, sp.p)
    mh = H.pow_bn(sp.g, msg, sp.p)
    return {
        "r": r,
        "g": sp.g, "p": sp.p, "h": pk,
        "m": msg,
        "c1_g_r": f"g^r = {sp.g}^{r} mod {sp.p} = {c1}",
        "s_h_r": f"h^r = {pk}^{r} mod {sp.p} = {s}",
        "mh_g_m": f"g^m = {sp.g}^{msg} mod {sp.p} = {mh}",
        "c2_s_mh": f"s·g^m = {s}×{mh} mod {sp.p} = {cipher.b}",
    }


@app.route("/api/ff/decrypt", methods=["POST"])
def ff_decrypt():
    """有限域解密"""
    data = request.json
    a, b = data["a"], data["b"]
    sk, p, g = data["sk"], data["p"], data["g"]
    sp = FFSetup.generate_system_parameters(p, g)
    from evote_crypto.ff_elgamal.models import Cipher
    ct = Cipher(a=a, b=b)
    plain = FFEnc.decrypt1(ct, sk, sp)
    # 解密步骤
    import evote_crypto.helper as H
    s = H.pow_bn(a, sk, p)
    s_inv = H.invm_bn(s, p)
    mh = H.mul_bn(b, s_inv, p)
    return jsonify({
        "success": True,
        "plaintext": plain,
        "steps": {
            "s_a_sk": f"a^sk = {a}^{sk} mod {p} = {s}",
            "s_inv": f"s⁻¹ = {s}⁻¹ mod {p} = {s_inv}",
            "mh": f"b·s⁻¹ = {b}×{s_inv} mod {p} = {mh}",
            "decode": f"解码 g^m={mh} → m={plain}",
        },
    })


@app.route("/api/ff/vote", methods=["POST"])
def ff_vote():
    """有限域投票"""
    data = request.json
    votes = data["votes"]  # list of 0 or 1
    p, g, pk = data["p"], data["g"], data["public_key"]
    sp = FFSetup.generate_system_parameters(p, g)
    ciphers = []
    for v in votes:
        if v == 1:
            ciphers.append(FFVoting.generate_yes_vote(sp, pk))
        else:
            ciphers.append(FFVoting.generate_no_vote(sp, pk))
    # 同态累加
    vote_sum = FFVoting.add_votes(ciphers, sp)
    return jsonify({
        "success": True,
        "ciphers": [{"a": c.a, "b": c.b} for c in ciphers],
        "sum": {"a": vote_sum.a, "b": vote_sum.b},
        "vote_count": len(votes),
    })


@app.route("/api/ff/tally", methods=["POST"])
def ff_tally():
    """有限域计票"""
    data = request.json
    votes = data["votes"]
    p, g, sk = data["p"], data["g"], data["sk"]
    pk = data["public_key"]
    sp = FFSetup.generate_system_parameters(p, g)
    ciphers = []
    for v in votes:
        if v == 1:
            ciphers.append(FFVoting.generate_yes_vote(sp, pk))
        else:
            ciphers.append(FFVoting.generate_no_vote(sp, pk))
    result = FFVoting.tally_votes(sp, sk, ciphers)
    summary = FFVoting.get_summary(len(votes), result)
    return jsonify({
        "success": True,
        "tally": result,
        "summary": {"total": summary.total, "yes": summary.yes, "no": summary.no},
    })


@app.route("/api/ff/proof/keygen", methods=["POST"])
def ff_proof_keygen():
    """密钥生成证明"""
    data = request.json
    p, g = data["p"], data["g"]
    sp, kp = FFSetup.generate_system_parameters_and_keys_zkp(p, g)
    uid = data.get("id", "demo")
    proof = FFKeyGenProof.generate(sp, kp, uid)
    valid = FFKeyGenProof.verify(sp, proof, kp.h, uid)
    return jsonify({
        "success": True,
        "proof": {"c": proof.c, "d": proof.d},
        "valid": valid,
        "params": {"p": sp.p, "q": sp.q, "g": sp.g, "h": kp.h, "sk": kp.sk},
        "steps": {
            "commitment": f"选择随机 a，计算承诺 b = g^a mod p",
            "challenge": f"挑战 c = H(id, h, b) mod q = {proof.c}",
            "response": f"响应 d = a + c·sk mod q = {proof.d}",
            "verify": f"验证: g^d ≟ b·h^c mod p → {'✓ 通过' if valid else '✗ 失败'}",
        },
    })


@app.route("/api/ff/proof/membership", methods=["POST"])
def ff_proof_membership():
    """成员证明"""
    data = request.json
    vote = data["vote"]  # 0 or 1
    p, g = data["p"], data["g"]
    uid = data.get("id", "vote-demo")
    sp, kp = FFSetup.generate_system_parameters_and_keys(p, g)
    if vote == 1:
        cipher = FFEnc.encrypt(1, sp, kp.h)
        proof = FFMembershipProof.generate_yes_proof(cipher, sp, kp.h, uid)
    else:
        cipher = FFEnc.encrypt(0, sp, kp.h)
        proof = FFMembershipProof.generate_no_proof(cipher, sp, kp.h, uid)
    valid = FFMembershipProof.verify(cipher, proof, sp, kp.h, uid)
    return jsonify({
        "success": True,
        "vote": vote,
        "valid": valid,
        "cipher": {"a": cipher.a, "b": cipher.b},
        "proof": {
            "a0": proof.a0, "a1": proof.a1, "b0": proof.b0, "b1": proof.b1,
            "c0": proof.c0, "c1": proof.c1, "f0": proof.f0, "f1": proof.f1,
        },
        "steps": {
            "encrypt": f"加密投票 {vote}: cipher = ({cipher.a}, {cipher.b})",
            "prove": f"生成 {'赞成' if vote==1 else '反对'} 证明",
            "verify": f"验证: g^f0≟a0·a^c0, g^f1≟a1·a^c1, h^f0≟b0·b^c0, h^f1≟b1·(b/g)^c1 → {'✓ 通过' if valid else '✗ 失败'}",
        },
    })


@app.route("/api/ff/proof/decrypt", methods=["POST"])
def ff_proof_decrypt():
    """解密证明"""
    data = request.json
    msg = data.get("message", 1)
    p, g = data["p"], data["g"]
    uid = data.get("id", "decrypt-demo")
    sp, kp = FFSetup.generate_system_parameters_and_keys(p, g)
    cipher = FFEnc.encrypt(msg, sp, kp.h)
    proof = FFDecProof.generate(cipher, sp, kp.sk, uid)
    valid = FFDecProof.verify(cipher, proof, sp, kp.h, uid)
    plain = FFEnc.decrypt1(cipher, kp.sk, sp)
    return jsonify({
        "success": True,
        "plaintext": plain,
        "valid": valid,
        "cipher": {"a": cipher.a, "b": cipher.b},
        "proof": {"a1": proof.a1, "b1": proof.b1, "f": proof.f, "d": proof.d},
        "steps": {
            "encrypt": f"加密消息 {msg}: cipher = ({cipher.a}, {cipher.b})",
            "decrypt": f"解密: m = {plain}",
            "prove": f"生成 Chaum-Pedersen 解密证明",
            "verify": f"验证: a^f≟a1·d^c, g^f≟b1·h^c → {'✓ 通过' if valid else '✗ 失败'}",
        },
    })


# ============================================================
# 椭圆曲线 ElGamal API
# ============================================================

@app.route("/api/ec/setup", methods=["POST"])
def ec_setup():
    """椭圆曲线系统设置"""
    sp = ECSetup.generate_system_parameters()
    kp = ECSetup.generate_key_pair()
    return jsonify({
        "success": True,
        "curve": "secp256k1",
        "params": {"p": str(sp.p)[:20] + "...", "n": str(sp.n)[:20] + "..."},
        "generator": {"x": str(sp.g.x)[:20] + "...", "y": str(sp.g.y)[:20] + "..."},
        "keypair": {
            "h": ECHelper.curve_point_to_string(kp.h)[:40] + "...",
            "sk": str(kp.sk)[:20] + "...",
        },
        "_h": ECHelper.curve_point_to_string(kp.h),
        "_sk": str(kp.sk),
        "_g": ECHelper.curve_point_to_string(sp.g),
    })


@app.route("/api/ec/encrypt", methods=["POST"])
def ec_encrypt():
    """椭圆曲线加密"""
    data = request.json
    vote = data.get("vote", 1)  # 1=yes, 0=no
    pk_str = data["public_key"]
    pk = ECHelper.deserialize_curve_point(pk_str)
    curve = get_curve()
    if vote == 1:
        msg = curve.g
    else:
        msg = curve.point(None, None)
    cipher = ECEnc.encrypt(msg, pk)
    return jsonify({
        "success": True,
        "vote": vote,
        "cipher": {
            "a": ECHelper.curve_point_to_string(cipher.a),
            "b": ECHelper.curve_point_to_string(cipher.b),
        },
    })


@app.route("/api/ec/vote", methods=["POST"])
def ec_vote():
    """椭圆曲线投票"""
    data = request.json
    votes = data["votes"]
    pk_str = data["public_key"]
    pk = ECHelper.deserialize_curve_point(pk_str)
    ciphers = []
    for v in votes:
        if v == 1:
            ciphers.append(ECVoting.generate_yes_vote(pk))
        else:
            ciphers.append(ECVoting.generate_no_vote(pk))
    return jsonify({
        "success": True,
        "count": len(votes),
        "ciphers": [
            {"a": ECHelper.curve_point_to_string(c.a), "b": ECHelper.curve_point_to_string(c.b)}
            for c in ciphers
        ],
    })


@app.route("/api/ec/tally", methods=["POST"])
def ec_tally():
    """椭圆曲线计票"""
    data = request.json
    votes = data["votes"]
    pk_str = data["public_key"]
    sk_str = data["secret_key"]
    sk = int(sk_str)
    pk = ECHelper.deserialize_curve_point(pk_str)
    ciphers = []
    for v in votes:
        if v == 1:
            ciphers.append(ECVoting.generate_yes_vote(pk))
        else:
            ciphers.append(ECVoting.generate_no_vote(pk))
    result = ECVoting.tally_votes(pk_str, sk, ciphers)
    summary = ECVoting.get_summary(len(votes), result)
    return jsonify({
        "success": True,
        "tally": result,
        "summary": {"total": summary.total, "yes": summary.yes, "no": summary.no},
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
