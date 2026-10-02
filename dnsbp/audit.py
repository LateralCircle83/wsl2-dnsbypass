"""污染审计：拿 DoH 的真值去比对本机明文解析的结果，给出分级与退出码。

分级口径（写死，便于脚本判断）：
  * canary 域（10 个被投毒靶子）出现假 IP 或与 DoH 真值不一致 → 污染
  * control 域（4 个国内/可达站点）同样比对，用于区分"选择性投毒"和"解析器全坏"
  * core 域（google/youtube/wikipedia）用于严重度：3/3 不一致 → 重污染
  * 任何 canary 都是假 IP（命中白名单外的经典投毒地址）→ 直接算重污染
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import wire
from .config import Config
from .doh import DohClient, DohError
from .transport import PlainDnsError, ask_a


@dataclass
class DomainResult:
    domain: str
    kind: str
    doh: list[str] = field(default_factory=list)
    local: list[str] = field(default_factory=list)
    fake_local: list[str] = field(default_factory=list)
    fake_doh: list[str] = field(default_factory=list)
    doh_ms: float = 0.0
    local_ms: float = 0.0
    note: str = ""
    error: str = ""

    @property
    def mismatch(self) -> bool:
        if not self.doh or not self.local:
            return False
        return set(self.doh) != set(self.local)

    @property
    def polluted(self) -> bool:
        """对照组只看"拿到假 IP"：国内/CDN 站点本地与 DoH 给出不同节点是正常的。"""
        if self.kind == "control":
            return bool(self.fake_local)
        return bool(self.fake_local) or self.mismatch

    def line(self) -> str:
        mark = "⚠" if self.polluted else "✓"
        if self.error:
            return f"{mark} {self.domain:<24} {self.error}"
        doh = ",".join(self.doh[:3]) or "-"
        local = ",".join(self.local[:3]) or "-"
        extra = f"  假IP:{','.join(self.fake_local[:2])}" if self.fake_local else ""
        note = f"  [{self.note}]" if self.note else ""
        return (
            f"{mark} {self.domain:<24} doh={doh:<38}({self.doh_ms:>5.0f}ms) "
            f"local={local:<38}({self.local_ms:>5.0f}ms){extra}{note}"
        )


@dataclass
class AuditReport:
    doh_url: str
    proxy: str
    doh_ok: bool = False
    doh_error: str = ""
    local_target: str = ""
    results: list[DomainResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    canary_names: list[str] = field(default_factory=list)
    control_names: list[str] = field(default_factory=list)
    core_names: list[str] = field(default_factory=list)

    # ---------------------------------------------------------- 统计

    def _by_names(self, names: list[str]) -> list[DomainResult]:
        wanted = set(names)
        return [r for r in self.results if r.domain in wanted]

    @property
    def canary(self) -> list[DomainResult]:
        return [r for r in self.results if r.kind == "canary"]

    @property
    def controls(self) -> list[DomainResult]:
        return self._by_names(self.control_names) if self.control_names else [
            r for r in self.results if r.kind == "control"
        ]

    @property
    def cores(self) -> list[DomainResult]:
        return self._by_names(self.core_names) if self.core_names else [
            r for r in self.results if r.kind == "core"
        ]

    @property
    def polluted_canary(self) -> int:
        return sum(1 for r in self.canary if r.polluted)

    @property
    def polluted_control(self) -> int:
        return sum(1 for r in self.controls if r.polluted)

    @property
    def polluted_core(self) -> int:
        return sum(1 for r in self.cores if r.polluted)

    @property
    def polluted_user(self) -> int:
        return sum(1 for r in self.results if r.kind == "user" and r.polluted)

    @property
    def fake_total(self) -> int:
        return sum(len(r.fake_local) for r in self.results)

    @property
    def verdict(self) -> str:
        if not self.doh_ok:
            return "doh-unreachable"
        if self.fake_total >= 3 or self.polluted_core >= 2:
            return "heavy"
        if self.polluted_canary >= 1:
            return "polluted"
        if self.polluted_user >= 1:
            return "light"
        return "clean"

    @property
    def exit_code(self) -> int:
        from . import EXIT_HEAVY, EXIT_LIGHT, EXIT_OK, EXIT_PREFLIGHT

        return {
            "doh-unreachable": EXIT_PREFLIGHT,
            "heavy": EXIT_HEAVY,
            "polluted": EXIT_HEAVY,
            "light": EXIT_LIGHT,
            "clean": EXIT_OK,
        }[self.verdict]

    @property
    def should_bind(self) -> bool:
        return self.verdict in {"heavy", "polluted"}

    # ---------------------------------------------------------- 呈现

    def summary(self) -> str:
        if not self.doh_ok:
            return f"DoH 不可用（{self.doh_url}）：{self.doh_error}"
        return (
            f"canary 污染 {self.polluted_canary}/{len(self.canary)}、"
            f"control {self.polluted_control}/{len(self.controls)}、"
            f"core {self.polluted_core}/{len(self.cores)}、"
            f"假 IP {self.fake_total} 个 ⇒ 判定 {self.verdict}"
        )

    def render(self) -> str:
        head = [
            f"DoH 端点   : {self.doh_url}" + (f"  (代理 {self.proxy})" if self.proxy else "  (直连)"),
            f"本机解析器 : {self.local_target}",
            f"结论       : {self.summary()}",
            "─" * 96,
        ]
        lines = [r.line() for r in self.results]
        return "\n".join(head + lines)

    def to_dict(self) -> dict:
        return {
            "doh_url": self.doh_url,
            "proxy": self.proxy,
            "doh_ok": self.doh_ok,
            "doh_error": self.doh_error,
            "local_target": self.local_target,
            "verdict": self.verdict,
            "summary": self.summary(),
            "polluted_canary": self.polluted_canary,
            "polluted_control": self.polluted_control,
            "polluted_core": self.polluted_core,
            "fake_total": self.fake_total,
            "started_at": self.started_at,
            "results": [
                {
                    "domain": r.domain,
                    "kind": r.kind,
                    "doh": r.doh,
                    "local": r.local,
                    "fake_local": r.fake_local,
                    "fake_doh": r.fake_doh,
                    "mismatch": r.mismatch,
                    "polluted": r.polluted,
                    "doh_ms": round(r.doh_ms, 1),
                    "local_ms": round(r.local_ms, 1),
                    "note": r.note,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


def probe_doh(cfg: Config, client: DohClient, log=print) -> tuple[bool, str]:
    """给启动闸门用：先确认 DoH 这一跳真的通。

    探测总时长要有上限（否则父进程 --wait 早就超时了，用户只看到"启动超时"）：
    每个域名用 min(timeout, 5s)，且一次失败后不再慢慢试第二个域名。
    """
    saved = client.timeout
    client.timeout = min(float(saved), 5.0)
    try:
        for domain in ("www.google.com", "example.com"):
            try:
                result = client.query_name(domain)
            except DohError as exc:
                log(f"[dnsbypass] DoH 探测失败（{domain}）：{exc}")
                continue
            answers = result.answers()
            if answers:
                log(f"[dnsbypass] DoH 探测通过（{domain} → {','.join(answers[:3])}，{result.elapsed_ms:.0f}ms）")
                return True, ""
            log(f"[dnsbypass] DoH 探测得到空应答（{domain}）")
    finally:
        client.timeout = saved
    return False, "DoH 端点不可用或解析为空"


def local_resolver(cfg: Config, log=print) -> str:
    """挑一个明文解析器来当"现状"样本；绝不要挑到我们自己。"""
    from . import resolvconf

    view = resolvconf.inspect()
    candidates = [s for s in view.nameservers if s not in {"127.0.0.1", "::1"}]
    candidates += [s for s in (cfg.get("fallback_nameservers") or []) if s not in {"127.0.0.1", "::1"}]
    candidates.append("10.255.255.254")
    if view.nameservers and not candidates:
        log("[dnsbypass] 当前 resolv.conf 只指向本机，样本解析器回落到 10.255.255.254")
    return candidates[0]


def _blacklisted(ip: str, entries: list[str]) -> bool:
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if entry.endswith(".*"):
            if ip.startswith(entry[:-1]):
                return True
        elif ip == entry:
            return True
    return False


def audit(
    cfg: Config,
    client: DohClient,
    user_domains: list[str] | None = None,
    log=print,
) -> AuditReport:
    report = AuditReport(
        doh_url=client.url,
        proxy=(client.proxy.source if client.proxy else "") or "",
        local_target=local_resolver(cfg, log=log),
        canary_names=list(cfg.get("canary_domains") or []),
        control_names=list(cfg.get("control_domains") or []),
        core_names=list(cfg.get("core_domains") or []),
    )

    ok, error = probe_doh(cfg, client, log=log)
    report.doh_ok = ok
    report.doh_error = error
    if not ok:
        if user_domains:
            log("[dnsbypass] DoH 不通，仍需为用户指定的域名给出可用的明文样本")
        else:
            return report

    blacklist = list(cfg.get("fake_ip_blacklist") or [])
    plan: list[tuple[str, str]] = []
    plan += [(d, "canary") for d in (cfg.get("canary_domains") or [])]
    plan += [(d, "core") for d in (cfg.get("core_domains") or [])]
    plan += [(d, "control") for d in (cfg.get("control_domains") or [])]
    for domain in user_domains or []:
        if domain not in {d for d, _ in plan}:
            plan.append((domain, "user"))

    seen: set[str] = set()
    for domain, kind in plan:
        if domain in seen:
            continue
        seen.add(domain)
        item = DomainResult(domain=domain, kind=kind)
        try:
            result = client.query_name(domain)
            item.doh = result.answers()
            item.doh_ms = result.elapsed_ms
        except DohError as exc:
            item.error = f"DoH 失败: {exc}"
        try:
            started = time.monotonic()
            item.local = ask_a(report.local_target, domain, timeout=min(cfg["timeout"], 5.0))
            item.local_ms = (time.monotonic() - started) * 1000.0
        except PlainDnsError as exc:
            item.local_ms = (time.monotonic() - started) * 1000.0
            item.error = (item.error + " | " if item.error else "") + f"明文失败: {exc}"
        item.fake_local = [ip for ip in item.local if wire.is_fake_ip(ip) or _blacklisted(ip, blacklist)]
        item.fake_doh = [ip for ip in item.doh if wire.is_fake_ip(ip) or _blacklisted(ip, blacklist)]
        if item.fake_doh:
            item.note = "DoH 本身给出可疑地址，样本不可信"
        elif kind == "control" and item.polluted:
            item.note = "对照组也拿到假 IP（解析器整体异常，结论需谨慎）"
        report.results.append(item)
    return report


def write_report(report: AuditReport, cfg: Config, name: str = "audit.json", log=print) -> Path:
    from .config import state_dir

    directory = state_dir(cfg)
    path = directory / name
    import json

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    return path