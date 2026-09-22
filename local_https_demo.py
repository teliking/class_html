#!/usr/bin/env python3
"""真实本机 HTTPS 请求；只绑定 127.0.0.1，不接收外部访问。
运行：python local_https_demo.py（依赖 cryptography，仅用于生成测试证书）。
证书仅写入临时目录；客户端显式信任该本机测试证书，不修改系统信任库。
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = b"Hello HTTPS: verified localhost TLS connection.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def make_test_certificate(folder: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = folder / "localhost.crt", folder / "localhost.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    if os.name == "posix":
        key_path.chmod(0o600)
    return cert_path, key_path


def main() -> None:
    if not ssl.HAS_TLSv1_3:
        raise RuntimeError("当前 Python/OpenSSL 不支持 TLS 1.3，请升级后再运行。")
    with tempfile.TemporaryDirectory(prefix="https-classroom-") as temp:
        cert_path, key_path = make_test_certificate(Path(temp))
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        server_ctx.load_cert_chain(str(cert_path), str(key_path))
        server_ctx.set_alpn_protocols(["http/1.1"])

        server = HTTPServer(("127.0.0.1", 0), Handler)
        server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client_ctx = ssl.create_default_context(cafile=str(cert_path))
            client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            client_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            client_ctx.set_alpn_protocols(["http/1.1"])
            host, port = server.server_address
            with socket.create_connection((host, port), timeout=5) as sock:
                with client_ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                    print("[PASS] negotiated:", tls.version())
                    print("[PASS] hostname and explicitly trusted test certificate verified")
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    chunks = []
                    while chunk := tls.recv(4096):
                        chunks.append(chunk)
            response = b"".join(chunks)
            if not response.startswith(b"HTTP/1.1 200 OK\r\n"):
                raise AssertionError("没有收到预期 HTTP 200 响应")
            print("[PASS] HTTP/1.1 200 OK")
            print(response.split(b"\r\n\r\n", 1)[1].decode().strip())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
