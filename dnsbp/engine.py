"""转发引擎：明文入（UDP/TCP）→ DoH 出 → TTL 缓存 → 回包 → 失败明文兜底。

两个必须做对的细节：
  1. **回包事务 ID 必须等于请求方的事务 ID**。DoH 上游通常原样回显，
     但缓存命中时存的是"第一次"的 ID；glibc 严格校验 ID，错了就丢弃并等到超时，
     表现为"越命中越查不出来"。（实测复现：发 0x2222 收回 0x1111。）
  2. **只在 RCODE=0 时入缓存**，失败不被钉住。
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import wire
from .doh import DohClient, DohError
from .transport import PlainDnsError, udp_query


class EngineError(RuntimeError):
    pass


COUNTERS = ("served", "hit", "miss", "doh_ok", "doh_fail", "fallback_ok", "fallback_fail", "malformed")


@dataclass
class Stats:
    served: int = 0
    hit: int = 0
    miss: int = 0
    doh_ok: int = 0
    doh_fail: int = 0
    fallback_ok: int = 0
    fallback_fail: int = 0
    malformed: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def bump(self, name: str, delta: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + delta)

    def as_dict(self) -> dict:
        with self._lock:
            return {name: getattr(self, name) for name in COUNTERS}

    def line(self) -> str:
        data = self.as_dict()
        return " ".join(f"{k}={v}" for k, v in data.items())


class Resolver:
    """把一条查询报文变成一条应答报文。"""

    def __init__(
        self,
        client: DohClient,
        fallback_servers: list[str] | None = None,
        ttl_cap: int = 300,
        default_ttl: int = 30,
        cache_max: int = 4096,
        doh_retries: int = 1,
        retry_backoff: float = 0.25,
        stats: Stats | None = None,
        log=print,
    ) -> None:
        self.client = client
        self.fallback_servers = list(fallback_servers or [])
        self.ttl_cap = ttl_cap
        self.default_ttl = default_ttl
        self.cache_max = cache_max
        # DoH 偶发 TLS 握手超时不该立刻降级成明文：先短退避重试
        self.doh_retries = max(0, int(doh_retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.stats = stats or Stats()
        self.log = log
        self._cache: dict[tuple[bytes, int], tuple[float, bytes]] = {}
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------ 缓存

    def cache_len(self) -> int:
        with self._cache_lock:
            return len(self._cache)

    def _cache_get(self, key) -> bytes | None:
        now = time.time()
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expiry, payload = entry
            if expiry <= now:
                self._cache.pop(key, None)
                return None
            return payload

    def _cache_put(self, key, payload: bytes, ttl: int) -> None:
        if ttl <= 0:
            return
        with self._cache_lock:
            if len(self._cache) >= self.cache_max:
                # 简单淘汰：先清过期的，还满就丢掉最早过期的一批
                now = time.time()
                expired = [k for k, (exp, _) in self._cache.items() if exp <= now]
                for k in expired:
                    self._cache.pop(k, None)
                if len(self._cache) >= self.cache_max:
                    for k, _ in sorted(self._cache.items(), key=lambda kv: kv[1][0])[: self.cache_max // 8 or 1]:
                        self._cache.pop(k, None)
            self._cache[key] = (time.time() + ttl, payload)

    # ------------------------------------------------------------ 解析

    def _fallback(self, pkt: bytes) -> tuple[bytes, str]:
        errors: list[str] = []
        for server in self.fallback_servers:
            try:
                resp = udp_query(server, pkt, timeout=min(self.client.timeout, 5.0))
                self.stats.bump("fallback_ok")
                return resp, f"fallback:{server}"
            except PlainDnsError as exc:
                errors.append(str(exc))
        self.stats.bump("fallback_fail")
        raise EngineError("DoH 与明文兜底都失败: " + "; ".join(errors or ["没有配置兜底解析器"]))

    def resolve(self, pkt: bytes) -> tuple[bytes | None, str]:
        """返回 (应答报文, 来源标签)。报文不合法时返回 (None, "malformed")。"""
        if len(pkt) < 12 or not wire.question_key(pkt):
            self.stats.bump("malformed")
            return None, "malformed"
        if wire.is_response(pkt):
            self.stats.bump("malformed")
            return None, "not-a-query"

        request_id = wire.txid(pkt)
        key = wire.question_key(pkt)
        cached = self._cache_get(key) if key else None
        if cached is not None:
            self.stats.bump("hit")
            return (wire.with_txid(cached, request_id) if request_id is not None else cached), "cache"

        self.stats.bump("miss")
        resp: bytes | None = None
        last_error: DohError | None = None
        source = "doh"
        for attempt in range(self.doh_retries + 1):
            try:
                resp = self.client.query_raw(pkt)
                self.stats.bump("doh_ok")
                last_error = None
                break
            except DohError as exc:
                last_error = exc
                if attempt < self.doh_retries:
                    self.log(f"[dnsbypass] DoH 第 {attempt + 1} 次失败，"
                             f"{self.retry_backoff:g}s 后重试: {exc}")
                    if self.retry_backoff:
                        time.sleep(self.retry_backoff)
        if last_error is not None:
            self.stats.bump("doh_fail")
            self.log(f"[dnsbypass] DoH 失败（含重试），转明文兜底: {last_error}")
            resp, source = self._fallback(pkt)
        assert resp is not None

        if request_id is not None:
            resp = wire.with_txid(resp, request_id)
        # 只缓存 DoH（可信）的应答：明文兜底的答案可能已被投毒，缓存它等于把污染留住
        if key and source == "doh" and wire.rcode(resp) == 0:
            ttl = wire.min_ttl(resp, cap=self.ttl_cap, default=self.default_ttl)
            self._cache_put(key, resp, ttl)
        return resp, source


class Server:
    """UDP + TCP 监听同一个端口，逐条交给 Resolver。"""

    def __init__(
        self,
        resolver: Resolver,
        host: str = "127.0.0.1",
        port: int = 5353,
        state_path: Path | None = None,
        state_interval: float = 5.0,
        max_workers: int = 32,
        log=print,
    ) -> None:
        self.resolver = resolver
        self.host = host
        self.port = port
        self.state_path = state_path
        self.state_interval = state_interval
        self.log = log
        self.started_at = time.time()
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dnsbypass")
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None

    # ------------------------------------------------------------ 套接字

    def open_sockets(self) -> None:
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((self.host, self.port))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((self.host, self.port))
            tcp.listen(64)
        except PermissionError as exc:
            raise EngineError(
                f"绑定 {self.host}:{self.port} 需要权限（端口 < {_unprivileged_floor()}）。"
                "用 sudo 起，或改用 >=1024 的端口。"
            ) from exc
        except OSError as exc:
            raise EngineError(f"绑定 {self.host}:{self.port} 失败: {exc}") from exc
        udp.settimeout(0.5)
        tcp.settimeout(0.5)
        self._udp, self._tcp = udp, tcp

    def sockets_bound(self) -> bool:
        return self._udp is not None and self._tcp is not None

    # ------------------------------------------------------------ 生命周期

    def serve_forever(self) -> None:
        if not self.sockets_bound():
            self.open_sockets()
        assert self._udp is not None and self._tcp is not None
        self.log(f"[dnsbypass] UDP+TCP 监听 {self.host}:{self.port} → {self.resolver.client.url}")
        threads = [
            threading.Thread(target=self._udp_loop, args=(self._udp,), daemon=True, name="udp-loop"),
            threading.Thread(target=self._tcp_loop, args=(self._tcp,), daemon=True, name="tcp-loop"),
        ]
        for thread in threads:
            thread.start()
        if self.state_path is not None:
            threading.Thread(target=self._state_loop, daemon=True, name="state-loop").start()
            self._write_state("running")
        try:
            while not self._stop.is_set():
                self._stop.wait(0.5)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._pool.shutdown(wait=False, cancel_futures=True)
        if self.state_path is not None:
            self._write_state("stopped")
        self.log(f"[dnsbypass] 已停止。{self.resolver.stats.line()}")

    # ------------------------------------------------------------ 循环

    def _udp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                pkt, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_udp, sock, pkt, peer)

    def _handle_udp(self, sock: socket.socket, pkt: bytes, peer) -> None:
        try:
            resp, _source = self.resolver.resolve(pkt)
            if resp is None:
                return
            self.resolver.stats.bump("served")
            sock.sendto(resp, peer)
        except (EngineError, OSError) as exc:
            self.log(f"[dnsbypass] UDP 处理失败 ({peer}): {exc}")

    def _tcp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._handle_tcp, conn, peer)

    def _handle_tcp(self, conn: socket.socket, peer) -> None:
        conn.settimeout(10.0)
        with conn:
            while not self._stop.is_set():
                try:
                    head = _read_exact(conn, 2)
                    if head is None:
                        return
                    (length,) = (int.from_bytes(head, "big"),)
                    pkt = _read_exact(conn, length)
                    if pkt is None:
                        return
                    resp, _source = self.resolver.resolve(pkt)
                    if resp is None:
                        return
                    self.resolver.stats.bump("served")
                    conn.sendall(len(resp).to_bytes(2, "big") + resp)
                except (EngineError, OSError, socket.timeout) as exc:
                    self.log(f"[dnsbypass] TCP 处理失败 ({peer}): {exc}")
                    return

    # ------------------------------------------------------------ 状态文件

    def state(self, status: str) -> dict:
        return {
            "status": status,
            "pid": os.getpid(),
            "host": self.host,
            "port": self.port,
            "doh_url": self.resolver.client.url,
            "fallback": self.resolver.fallback_servers,
            "started_at": self.started_at,
            "updated_at": time.time(),
            "stats": self.resolver.stats.as_dict(),
            "cache_entries": self.resolver.cache_len(),
        }

    def _write_state(self, status: str) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state(status), ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.state_path)
        except OSError as exc:  # 状态文件写不了不该影响解析
            self.log(f"[dnsbypass] 状态文件写入失败: {exc}")

    def _state_loop(self) -> None:
        while not self._stop.wait(self.state_interval):
            self._write_state("running")


# ---------------------------------------------------------------- 工具

def _read_exact(conn: socket.socket, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        try:
            chunk = conn.recv(count - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _unprivileged_floor() -> int:
    try:
        return int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip())
    except (OSError, ValueError):
        return 1024


def drop_privileges(log=print) -> str | None:
    """以 root 绑定端口后降权到调用者（sudo 场景）。"""
    if os.geteuid() != 0:
        return None
    uid_raw, gid_raw = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid_raw or not gid_raw:
        return None
    uid, gid = int(uid_raw), int(gid_raw)
    try:
        os.setgroups([gid])
        os.setgid(gid)
        os.setuid(uid)
    except OSError as exc:  # pragma: no cover
        return f"降权失败（仍以 root 运行）: {exc}"
    return f"已降权到 uid={uid} gid={gid}"


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True