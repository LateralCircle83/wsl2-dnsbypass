"""明文 DNS 传输（仅用于两件事：保命兜底、以及审计系统解析器）。

注意：本环境里明文 53 会被抢答，所以这里**只作为测量工具和最后一道兜底**，
绝不作为正常解析路径。
"""
from __future__ import annotations

import socket

from . import wire


class PlainDnsError(RuntimeError):
    pass


def udp_query(server: str, pkt: bytes, timeout: float = 3.0, port: int = 53) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, port))
        data, _peer = sock.recvfrom(65535)
        return data
    except socket.timeout as exc:
        raise PlainDnsError(f"{server}:{port} 明文查询超时（{timeout}s）") from exc
    except OSError as exc:
        raise PlainDnsError(f"{server}:{port} 明文查询失败: {exc}") from exc
    finally:
        sock.close()


def tcp_query(server: str, pkt: bytes, timeout: float = 3.0, port: int = 53) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, port))
        sock.sendall(len(pkt).to_bytes(2, "big") + pkt)
        head = _read_exact(sock, 2)
        (length,) = (int.from_bytes(head, "big"),)
        return _read_exact(sock, length)
    except (socket.timeout, OSError) as exc:
        raise PlainDnsError(f"{server}:{port} 明文 TCP 查询失败: {exc}") from exc
    finally:
        sock.close()


def _read_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise PlainDnsError("明文 TCP 连接被提前关闭")
        buf += chunk
    return buf


def ask_a(server: str, name: str, timeout: float = 3.0, port: int = 53) -> list[str]:
    """向指定解析器问一条 A 记录，返回地址列表（不校验 ID 之外的语义）。"""
    pkt = wire.build_query(name, wire.QTYPE_A)
    resp = udp_query(server, pkt, timeout=timeout, port=port)
    if not wire.is_response(resp):
        raise PlainDnsError(f"{server} 返回的不是响应报文")
    if wire.txid(resp) != wire.txid(pkt):
        raise PlainDnsError(f"{server} 返回的报文事务 ID 不匹配")
    return wire.answers_of(resp, wire.QTYPE_A)