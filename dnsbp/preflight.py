"""启动前体检：把"起不来/起来了也没用"的原因在启动前一次说清。

每一检查项给 ok / warn / fail + 一句可执行的提示；fail 只保留真正致命的
（DoH 不通、监听端口占不上、Python 太老）。其余是 warn，让用户自己判断。
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import resolvconf
from .config import Config, state_dir
from .doh import DohClient
from .engine import _unprivileged_floor, process_alive

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    hint: str = ""

    def line(self) -> str:
        icon = {OK: "✓", WARN: "!", FAIL: "✗"}[self.status]
        tail = f"  → {self.hint}" if self.hint else ""
        return f"{icon} {self.name:<18} {self.detail}{tail}"


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str, hint: str = "") -> None:
        self.checks.append(Check(name, status, detail, hint))

    @property
    def fatal(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def ok(self) -> bool:
        return not self.fatal

    def render(self) -> str:
        return "\n".join(c.line() for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint} for c in self.checks],
        }


def port_probe(host: str, port: int, udp: bool = True, tcp: bool = True) -> tuple[bool, str]:
    socks: list[socket.socket] = []
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            socks.append(sock)
        if tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(4)
            socks.append(sock)
        return True, f"{'UDP+' if udp else ''}{'TCP' if tcp else 'UDP'} {host}:{port} 可绑定"
    except PermissionError:
        return False, f"{host}:{port} 需要 root（端口 < {_unprivileged_floor()}）"
    except OSError as exc:
        return False, f"{host}:{port} 绑定失败: {exc}"
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass


def tcp_touch(host: str, port: int, timeout: float = 2.5) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port} 可连接"
    except OSError as exc:
        return False, f"{host}:{port} 不可连接: {exc}"


def loopback_delivery(host: str, port: int, timeout: float = 2.0) -> tuple[bool | None, str]:
    """发包给自己，验证这个 (host, port) 上"绑定成功 ≠ 收得到"。

    WSL 镜像模式下环回被 Windows 共享：Windows 侧持有 127.0.0.1:53，Linux 侧
    绑定同一地址会成功，但发给它的包被吞掉（甚至连 sendto 都会卡住）——所以
    这个自测必须在超时保护下跑，卡住即判失败。返回 (None, 说明) 表示没权限验。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except PermissionError:
        return None, f"{host}:{port} 需要 root 才能验（绑定时会验）"
    except OSError as exc:
        return None, f"{host}:{port} 无法绑定（可能引擎在跑）: {exc}"
    sock.settimeout(timeout)
    result: list[Exception | None] = [None]

    def _send() -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"dnsbypass-loopback-probe", (host, port))
        except Exception as exc:  # pragma: no cover - 平台相关
            result[0] = exc
        finally:
            client.close()

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()
    try:
        data, _ = sock.recvfrom(64)
        if data:
            return True, f"{host}:{port} 环回可用（收得到自己发的包）"
        return False, f"{host}:{port} 环回异常（收到空包）"
    except socket.timeout:
        if result[0] is not None:
            return False, f"{host}:{port} 发包本身就卡住/失败（{result[0]}）→ 换 bind_host"
        if thread.is_alive():
            return False, f"{host}:{port} 发包卡住（镜像模式下被 Windows 侧吞掉）→ 换 bind_host"
        return False, f"{host}:{port} 收不到自己发的包（绑定成功 ≠ 可用）→ 换 bind_host"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_python(report: PreflightReport) -> None:
    version = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info >= (3, 10):
        report.add("python", OK, f"{version} ({sys.executable})")
    else:
        report.add("python", FAIL, f"{version} 太旧", "需要 3.10+（用了 tomllib / X | Y 语法）")


def check_proxy(report: PreflightReport, cfg: Config, client: DohClient) -> None:
    proxy = client.proxy
    if proxy is None or not proxy.has_any():
        report.add("代理", WARN, "环境里没有任何 http_proxy/https_proxy",
                   "DoH 端点若直连不通就必须给代理（本项目只出站到 DoH）")
        return
    if proxy.no_proxy:
        covered = any(proxy.no_proxy_entries())
        report.add("代理", WARN if covered else OK,
                   f"{proxy.source} = {proxy.for_scheme('https') or proxy.for_scheme('http')}"
                   + (f"（no_proxy 有 {len(proxy.no_proxy_entries())} 条）" if covered else ""),
                   "注意：DoH 那一跳我们强制走代理，不受 no_proxy 影响" if covered else "")
    else:
        report.add("代理", OK, f"{proxy.source} = {proxy.for_scheme('https') or proxy.for_scheme('http')}")
    target = proxy.for_scheme("https") or proxy.for_scheme("http")
    if target:
        parts = urlsplit(target)
        host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
        if host:
            ok, detail = tcp_touch(host, port)
            report.add("代理可达", OK if ok else FAIL, detail,
                       "HTTP 代理不通，DoH 也出不去" if not ok else "")
    if client.host:
        hosts_file = Path("/etc/hosts")
        pinned = False
        try:
            for line in hosts_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if line and client.host in line.split()[1:]:
                    pinned = True
                    break
        except OSError:
            pass
        if pinned:
            report.add("DoH 域名", OK, f"{client.host} 已在 /etc/hosts 钉住")


def check_doh(report: PreflightReport, cfg: Config, client: DohClient, live: bool = True) -> None:
    if not live:
        report.add("DoH 探测", WARN, "已跳过（--no-probe）")
        return
    from .audit import probe_doh

    ok, error = probe_doh(cfg, client, log=lambda *_: None)
    report.add("DoH 探测", OK if ok else FAIL, ok and f"{client.url} 可用" or error,
               "" if ok else "换端点或修代理；DoH 不通时本项目没有意义")


def check_resolv(report: PreflightReport) -> None:
    view = resolvconf.inspect()
    detail = f"{view.path}"
    if view.is_symlink:
        detail += f" → {view.link_target}"
    detail += f"  nameserver={','.join(view.nameservers) or 'none'}"
    status, hint = OK, ""
    if view.stub_resolved:
        status, hint = FAIL, "由 systemd-resolved 管着，先处理它再谈接管"
    elif not view.exists:
        status, hint = WARN, "文件不存在，接管时会新建；回滚时会删除"
    elif not view.writable:
        status, hint = WARN, "当前用户不可写，bind 需要 sudo"
    report.add("resolv.conf", status, detail, hint)


def check_ports(report: PreflightReport, cfg: Config) -> None:
    ok, detail = port_probe(cfg["listen_host"], cfg["listen_port"])
    report.add("监听端口", OK if ok else FAIL, detail,
               "换个 >=1024 的空闲端口" if not ok else "")
    if cfg["bind_port"] == 53:
        bind_host = cfg["bind_host"]
        ok53, detail53 = port_probe(bind_host, 53)
        report.add("接管端口 53", OK if ok53 else WARN, detail53,
                   "bind 时用 sudo 起" if not ok53 else "")
        if ok53:
            delivered, why = loopback_delivery(bind_host, 53)
            if delivered is None:
                report.add("接管环回", WARN, why, "以 sudo 再跑一次 preflight 可验证")
            else:
                report.add(
                    "接管环回", OK if delivered else FAIL, why,
                    "" if delivered else
                    "WSL 镜像模式下 127.0.0.1:53 被 Windows 侧占用：绑定会成功但收不到包。"
                    "把 config.toml 的 bind_host 换成 127.0.0.2/127.0.0.55 之类",
                )


def check_engine(report: PreflightReport, cfg: Config) -> None:
    path = state_dir(cfg) / "engine.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        report.add("运行状态", OK, "没有正在运行的实例")
        return
    pid = int(data.get("pid") or 0)
    if data.get("status") == "running" and process_alive(pid):
        report.add("运行状态", WARN, f"已有实例在跑（pid={pid}, {data.get('host')}:{data.get('port')}）",
                   "先 `dnsbypass stop`，或换端口")
    else:
        report.add("运行状态", OK, f"状态文件存在但进程已不在（pid={pid}）")


def check_tls(report: PreflightReport, client: DohClient) -> None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    except ssl.SSLError as exc:
        report.add("TLS", FAIL, f"默认 SSL 上下文不可用: {exc}")
        return
    report.add("TLS", OK, f"默认 CA 可用（{ssl.OPENSSL_VERSION}），DoH 走证书校验")


def run(cfg: Config, client: DohClient, live_probe: bool = True) -> PreflightReport:
    report = PreflightReport()
    check_python(report)
    check_tls(report, client)
    check_proxy(report, cfg, client)
    check_doh(report, cfg, client, live=live_probe)
    check_resolv(report)
    check_ports(report, cfg)
    check_engine(report, cfg)
    return report