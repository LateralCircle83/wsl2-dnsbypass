"""DNS 线格式的最小工具集。

原则：**只读不重构**。转发路径上不动报文任何字节（除了回包事务 ID），
这里的解析只服务于：(a) 缓存键、(b) TTL、(c) 审计与预检的答案展示。

不覆盖的格式情况一律"放弃而不是猜"：解析失败返回 None，调用方必须能接受。
"""
from __future__ import annotations

import ipaddress
import random
import struct

QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28

_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 65: "HTTPS",
}
_RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED",
}


def type_name(rtype: int) -> str:
    return _TYPE_NAMES.get(rtype, f"TYPE{rtype}")


def rcode_name(rcode: int | None) -> str:
    if rcode is None:
        return "?"
    return _RCODE_NAMES.get(rcode, f"RCODE{rcode}")


# ---------------------------------------------------------------- 报文头部

def txid(pkt: bytes) -> int | None:
    if len(pkt) < 2:
        return None
    return struct.unpack("!H", pkt[:2])[0]


def with_txid(pkt: bytes, new_id: int) -> bytes:
    """把回包的事务 ID 改成请求方的 ID（缓存命中时必须做）。"""
    if len(pkt) < 2:
        return pkt
    return struct.pack("!H", new_id & 0xFFFF) + pkt[2:]


def rcode(pkt: bytes) -> int | None:
    if len(pkt) < 12:
        return None
    return pkt[3] & 0x0F


def is_response(pkt: bytes) -> bool:
    return len(pkt) >= 12 and bool(pkt[2] & 0x80)


def header_counts(pkt: bytes) -> tuple[int, int, int, int] | None:
    if len(pkt) < 12:
        return None
    return struct.unpack("!HHHH", pkt[4:12])


# ---------------------------------------------------------------- 名字

def skip_name(buf: bytes, i: int) -> int | None:
    """跳过名字，返回其后的偏移；压缩指针按 2 字节计入。"""
    while True:
        if i >= len(buf):
            return None
        length = buf[i]
        if length == 0:
            return i + 1
        if length & 0xC0 == 0xC0:
            return i + 2 if i + 2 <= len(buf) else None
        if length & 0xC0:  # 0x40/0x80 是保留编码，不猜
            return None
        i += 1 + length


def decode_name(buf: bytes, i: int, max_steps: int = 128) -> tuple[str | None, int | None]:
    """完整解码（跟随压缩指针），返回 (名字, 名字在原报文中的结束偏移)。"""
    labels: list[bytes] = []
    seen: set[int] = set()
    end: int | None = None
    jumped = False
    steps = 0
    while True:
        if i >= len(buf) or steps > max_steps:
            return None, None
        steps += 1
        length = buf[i]
        if length == 0:
            if not jumped:
                end = i + 1
            break
        if length & 0xC0 == 0xC0:
            if i + 1 >= len(buf):
                return None, None
            pointer = ((length & 0x3F) << 8) | buf[i + 1]
            if not jumped:
                end = i + 2
            if pointer in seen:
                return None, None
            seen.add(pointer)
            jumped = True
            i = pointer
            continue
        if length & 0xC0:
            return None, None
        i += 1
        chunk = buf[i:i + length]
        if len(chunk) != length:
            return None, None
        labels.append(chunk)
        i += length
    ascii_name = b".".join(labels).decode("ascii", "backslashreplace")
    return (ascii_name if ascii_name else "."), end


def qname_text(pkt: bytes) -> str | None:
    name, _ = decode_name(pkt, 12)
    return name


def question_key(pkt: bytes) -> tuple[bytes, int] | None:
    """缓存键 = QNAME 的原始编码字节 + qtype（不做大小写归一化）。"""
    if len(pkt) < 12:
        return None
    i = skip_name(pkt, 12)
    if i is None or i + 4 > len(pkt):
        return None
    qtype, _qclass = struct.unpack("!HH", pkt[i:i + 4])
    return bytes(pkt[12:i]), qtype


# ---------------------------------------------------------------- TTL

def min_ttl(resp: bytes, cap: int = 300, default: int = 30) -> int:
    """取所有 RR 的最小 TTL，封顶 cap、下限 1；解析失败返回 default。"""
    counts = header_counts(resp)
    if counts is None:
        return default
    qd, an, ns, ar = counts
    i: int | None = 12
    for _ in range(qd):
        if i is None:
            return default
        i = skip_name(resp, i)
        if i is None:
            return default
        i += 4
    ttls: list[int] = []
    for _ in range(an + ns + ar):
        if i is None:
            break
        i = skip_name(resp, i)
        if i is None or i + 10 > len(resp):
            break
        _rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
        i += 10 + rdlen
        if i > len(resp):
            break
        ttls.append(ttl)
    if not ttls:
        return default
    return max(1, min(cap, min(ttls)))


# ---------------------------------------------------------------- 构造与解析

def _encode_label(label: str) -> bytes:
    try:
        return label.encode("ascii")
    except UnicodeEncodeError:
        return label.encode("idna")


def build_query(name: str, qtype: int = QTYPE_A, qid: int | None = None) -> bytes:
    if qid is None:
        qid = random.randrange(0, 0x10000)
    labels = [part for part in name.strip().rstrip(".").split(".") if part]
    qname = b"".join(bytes([len(_encode_label(p))]) + _encode_label(p) for p in labels) + b"\x00"
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_records(pkt: bytes) -> list[dict]:
    """解析 question 之后的全部 RR（含 authority/additional），尽力而为。"""
    out: list[dict] = []
    counts = header_counts(pkt)
    if counts is None:
        return out
    qd, an, ns, ar = counts
    i: int | None = 12
    for _ in range(qd):
        if i is None:
            return out
        i = skip_name(pkt, i)
        if i is None:
            return out
        i += 4
    for _ in range(an + ns + ar):
        if i is None:
            break
        name, after = decode_name(pkt, i)
        if name is None or after is None or after + 10 > len(pkt):
            break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", pkt[after:after + 10])
        rdata_at = after + 10
        if rdata_at + rdlen > len(pkt):
            break
        record = {"name": name, "rtype": rtype, "type": type_name(rtype), "ttl": ttl, "class": rclass}
        raw = pkt[rdata_at:rdata_at + rdlen]
        if rtype == QTYPE_A and rdlen == 4:
            record["data"] = str(ipaddress.IPv4Address(raw))
        elif rtype == QTYPE_AAAA and rdlen == 16:
            record["data"] = str(ipaddress.IPv6Address(raw))
        elif rtype == QTYPE_CNAME:
            record["data"] = decode_name(pkt, rdata_at)[0]
        elif rtype == 41:  # OPT
            record["data"] = f"opt({rdlen}B)"
        else:
            record["data"] = raw.hex()
        out.append(record)
        i = rdata_at + rdlen
    return out


def answers_of(pkt: bytes, rtype: int = QTYPE_A) -> list[str]:
    return [r["data"] for r in parse_records(pkt) if r["rtype"] == rtype and r["class"] == 1]


# ---------------------------------------------------------------- 地址判断

def is_public_ip(text: str) -> bool:
    """与 dsh-web-fetch-http 的判定口径对齐：非 unicast 就拒。"""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def is_fake_ip(text: str) -> bool:
    """合成地址（fake-IP）判定：保留段，永远不该出现在真实答案里。"""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        return ip in ipaddress.ip_network("fd00::/8") or ip in ipaddress.ip_network("fc00::/7")
    return ip in ipaddress.ip_network("198.18.0.0/15")