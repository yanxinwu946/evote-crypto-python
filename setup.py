from setuptools import setup, find_packages

setup(
    name="evote-crypto",
    version="0.1.0",
    description="电子投票密码学库 - ElGamal 加密系统，支持有限域和椭圆曲线",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="改写自 meck93/evote-crypto",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.15.0",
        "ecdsa>=0.18.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
    ],
)
