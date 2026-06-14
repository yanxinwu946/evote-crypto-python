# 电子投票密码学库 (eVoting Cryptography)

> 一个用于电子投票的 Python 密码学库。实现了基于有限域和椭圆曲线的 ElGamal 加密系统，结合非交互式零知识证明和分布式密钥生成。

## 概述

本库使用以下密码学概念来实现电子投票系统的安全属性：

- **ElGamal 加密系统**：投票的加密和解密
- **同态加密**：对加密投票进行计数
- **分布式密钥生成**：多方非对称密钥生成
- **非交互式零知识证明**：证明私钥知识、投票正确性和解密正确性

库分为两个部分：
- **有限域实现** (`evote_crypto/ff_elgamal/`)：基于有限域的 ElGamal
- **椭圆曲线实现** (`evote_crypto/ec_elgamal/`)：基于椭圆曲线 (Curve25519) 的 ElGamal

两个部分主要包含以下模块：

- `system_setup`：系统参数生成、密钥对生成、公钥合并
- `encryption`：投票加密/解密、同态加法、份额解密
- `voting`：生成赞成/反对投票、计票
- `proofs`：
  - `key_generation`：私钥知识证明（Schnorr 证明）
  - `membership`：投票成员证明（析取 Chaum-Pedersen 证明）
  - `decryption`：正确解密证明（Chaum-Pedersen 证明）

## 安装

```bash
pip install -e .
```

## 依赖

- `pycryptodome`：提供 Keccak-256 哈希函数
- `ecdsa`：椭圆曲线操作

## 使用示例

### 有限域 ElGamal

```python
from evote_crypto.ff_elgamal import SystemSetup, Encryption, Voting

# 系统设置
sp = SystemSetup.generate_system_parameters(p=11, g=2)
kp = SystemSetup.generate_key_pair(sp)

# 加密投票
cipher = Encryption.encrypt(1, sp, kp.h)

# 解密
plaintext = Encryption.decrypt1(cipher, kp.sk, sp)
```

### 椭圆曲线 ElGamal

```python
from evote_crypto.ec_elgamal import SystemSetup, Encryption, Voting

# 系统设置
sp = SystemSetup.generate_system_parameters()
kp = SystemSetup.generate_key_pair()

# 投票和计票
yes_vote = Voting.generate_yes_vote(kp.h)
no_vote = Voting.generate_no_vote(kp.h)
```

## 许可证

本项目基于 MIT 许可证发布。

## 原始项目

本项目从 TypeScript 版本改写而来：
- 原始仓库：[meck93/evote-crypto](https://github.com/meck93/evote-crypto)
- 原作者：Moritz Eck, Alex Scheitlin, Nik Zaugg
