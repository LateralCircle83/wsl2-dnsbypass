"""代理环境快照。

为什么要单独一个模块：WSL 的 autoProxy 往**每个进程**注入 http_proxy/https_proxy，
而 `sudo` 默认 env_reset 会把这些变量丢掉。所以任何需要提权的步骤都必须
"先快照、再传进去"，不能让提权后的进程自己去读环境。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

CANONICAL_KEYS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


@dataclass
class ProxyEnv:
    http: str = ""
    https: str = ""
    all: str = ""
    no_proxy: str = ""
    source: str = "env"
    raw: dict[str, str] = field(default_factory=dict)

    def for_scheme(self, scheme: str) -> str:
        scheme = scheme.lower()
        if scheme == "http":
            return self.http or self.https or self.all
        return self.https or self.http or self.all

    def has_any(self) -> bool:
        return bool(self.http or self.https or self.all)

    def proxy_map(self) -> dict[str, str]:
        """给 urllib ProxyHandler 用的字典（不塞 no_proxy：DoH 那一跳必须走代理）。"""
        mapping: dict[str, str] = {}
        if self.http:
            mapping["http"] = self.http
        if self.https:
            mapping["https"] = self.https
        if not mapping and self.all:
            mapping["http"] = self.all
            mapping["https"] = self.all
        return mapping

    def no_proxy_entries(self) -> list[str]:
        return [item.strip() for item in self.no_proxy.split(",") if item.strip()]

    def as_dict(self) -> dict[str, str]:
        return {
            "http": mask(self.http),
            "https": mask(self.https),
            "all": mask(self.all),
            "no_proxy": self.no_proxy,
            "source": self.source,
        }


def mask(url: str) -> str:
    """去掉 URL 里的凭据后再展示。"""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.username or parts.password:
        netloc = parts.hostname or ""
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return url


def snapshot(environ: dict[str, str] | None = None) -> ProxyEnv:
    env = environ if environ is not None else os.environ
    lowered = {key.lower(): value for key, value in env.items()}
    found = {key: lowered.get(key, "") for key in CANONICAL_KEYS}
    return ProxyEnv(
        http=found["http_proxy"],
        https=found["https_proxy"],
        all=found["all_proxy"],
        no_proxy=found["no_proxy"],
        source="env",
        raw=found,
    )


def recover_from_processes(uid: int | None = None, self_pid: int | None = None) -> ProxyEnv:
    """sudo 下 env_reset 会清掉代理变量，这里从**调用者身份的其他进程**里捡回来。

    只在 `SUDO_USER` 存在（即我们是被提权启动的）时才该调用。做法是扫 /proc/*/environ，
    找同 uid 的某个进程（通常是用户的 shell 或 dsh）里残留的 http_proxy/https_proxy。
    提权进程读得到别人的 environ，普通身份读不到，失败就安静返回空。
    """
    if uid is None:
        raw_uid = os.environ.get("SUDO_UID")
        if not raw_uid or not raw_uid.isdigit():
            return ProxyEnv(source="none")
        uid = int(raw_uid)
    me = self_pid if self_pid is not None else os.getpid()
    parent = os.getppid()
    candidates: list[tuple[str, dict[str, str]]] = []
    try:
        entries = sorted(os.listdir("/proc"))
    except OSError:
        return ProxyEnv(source="none")
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid in (me, parent):
            continue
        path = f"/proc/{name}/environ"
        try:
            if os.stat(f"/proc/{name}").st_uid != uid:
                continue
            with open(path, "rb") as handle:
                blob = handle.read()
        except OSError:
            continue
        found: dict[str, str] = {}
        for item in blob.split(b"\0"):
            if b"=" not in item:
                continue
            key, _, value = item.partition(b"=")
            lowered = key.decode("utf-8", "replace").lower()
            if lowered in CANONICAL_KEYS and value:
                found[lowered] = value.decode("utf-8", "replace")
        if found.get("http_proxy") or found.get("https_proxy") or found.get("all_proxy"):
            candidates.append((f"/proc/{pid}/environ(uid {uid})", found))
    if not candidates:
        return ProxyEnv(source="none")
    source, found = candidates[0]
    return ProxyEnv(
        http=found.get("http_proxy", ""),
        https=found.get("https_proxy", ""),
        all=found.get("all_proxy", ""),
        no_proxy=found.get("no_proxy", ""),
        source=source,
        raw=found,
    )


def effective_proxy(env: ProxyEnv, override: str = "") -> ProxyEnv:
    """配置里的 upstream_proxy 覆盖环境（"真实代理入口"显式指定）。"""
    if not override:
        return env
    merged = ProxyEnv(
        http=override, https=override, all=override, no_proxy=env.no_proxy,
        source="config",
    )
    return merged


def describe(env: ProxyEnv) -> list[str]:
    lines = [
        f"来源      : {env.source}",
        f"http_proxy : {mask(env.http) or '(未设置)'}",
        f"https_proxy: {mask(env.https) or '(未设置)'}",
    ]
    if env.all:
        lines.append(f"all_proxy  : {mask(env.all)}")
    if env.no_proxy:
        lines.append(f"no_proxy   : {env.no_proxy}")
    return lines


def no_proxy_covers(env: ProxyEnv, host: str) -> bool:
    """宽松判断 host 是否落在 no_proxy 里（会返回真命中的条目名）。"""
    host = host.lower()
    for entry in env.no_proxy_entries():
        entry = entry.lower()
        if entry == host:
            return True
        if entry.startswith("*"):
            return True
        if entry.startswith(".") and (host.endswith(entry) or host == entry[1:]):
            return True
        if host.endswith("." + entry):
            return True
    return False