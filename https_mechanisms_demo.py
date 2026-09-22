#!/usr/bin/env python3
"""教学用安全通信实验，不是 TLS 实现，不用于保护生产数据。

依赖：pip install cryptography
运行：python https_mechanisms_demo.py
资料：cryptography 官方文档（X25519、Ed25519、HKDF、AESGCM）。
信任简化：客户端提前可信地获得服务器的签名公钥，代替证书链验证。
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Callable, Type

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def raw_public(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def derive_key(shared: bytes, transcript: bytes, direction: bytes) -> bytes:
    """教学用派生方法；不是 TLS 1.3 的完整 HKDF-Expand-Label 密钥日程。"""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"classroom-demo/v1/" + direction + hashlib.sha256(transcript).digest(),
    ).derive(shared)


def must_reject(action: Callable[[], object], exc: Type[Exception], label: str) -> None:
    try:
        action()
    except exc:
        print(f"[PASS] {label}: {exc.__name__}")
    else:
        raise AssertionError(f"没有拒绝 {label}，实验失败")


def main() -> None:
    # 实验 0：小整数 DH 的算术关系。小参数完全不安全！
    p, g, a, b = 23, 5, 6, 15
    A, B = pow(g, a, p), pow(g, b, p)
    assert pow(B, a, p) == pow(A, b, p) == 2
    print(f"[PASS] toy DH: A={A}, B={B}, shared=2 (INSECURE parameters)")

    # 长期身份签名密钥与本次临时协商密钥分开。
    signing_key = Ed25519PrivateKey.generate()
    trusted_key = signing_key.public_key()  # 预置可信来源，不从攻击者处随意替换
    client_private = X25519PrivateKey.generate()
    server_private = X25519PrivateKey.generate()

    # 对身份、双方临时公钥及随机数共同签名，绑定本次握手。
    record = {
        "protocol": "classroom-demo/v1; X25519; Ed25519; AES-256-GCM",
        "server_name": "class.example",
        "client_public": raw_public(client_private).hex(),
        "server_public": raw_public(server_private).hex(),
        "client_random": os.urandom(32).hex(),
        "server_random": os.urandom(32).hex(),
    }
    transcript = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    signature = signing_key.sign(transcript)
    trusted_key.verify(signature, transcript)

    client_shared = client_private.exchange(server_private.public_key())
    server_shared = server_private.exchange(client_private.public_key())
    if client_shared != server_shared:
        raise AssertionError("共享秘密不相等")
    client_key = derive_key(client_shared, transcript, b"c2s")
    server_key = derive_key(server_shared, transcript, b"c2s")
    reverse_key = derive_key(server_shared, transcript, b"s2c")
    assert client_key == server_key and client_key != reverse_key
    print("[PASS] shared secret and c2s keys match; s2c key is separate")

    msg = b"POST /login | student=20260001&password=demo-only"
    aad = b"classroom-demo/v1; direction=c2s; sequence=0"
    # 本实验每次运行都生成新密钥，且每把发送密钥只加密这一条消息。
    # 一般多消息系统必须专门管理 nonce，保证同一密钥下不重复。
    nonce = os.urandom(12)
    packet = AESGCM(client_key).encrypt(nonce, msg, aad)
    recovered = AESGCM(server_key).decrypt(nonce, packet, aad)
    assert recovered == msg
    print("[PASS] normal message recovered")

    changed = bytearray(packet)
    changed[0] ^= 1
    must_reject(
        lambda: AESGCM(server_key).decrypt(nonce, bytes(changed), aad),
        InvalidTag, "tampering rejected",
    )

    attacker_signature = Ed25519PrivateKey.generate().sign(transcript)
    must_reject(
        lambda: trusted_key.verify(attacker_signature, transcript),
        InvalidSignature, "forged identity rejected",
    )

    changed_record = dict(record)
    changed_record["server_public"] = raw_public(X25519PrivateKey.generate()).hex()
    changed_transcript = json.dumps(
        changed_record, sort_keys=True, separators=(",", ":")
    ).encode()
    must_reject(
        lambda: trusted_key.verify(signature, changed_transcript),
        InvalidSignature, "replaced key share rejected",
    )
    print("Teaching demo only: no TLS record framing, certificate chain, or network state machine.")


if __name__ == "__main__":
    main()
