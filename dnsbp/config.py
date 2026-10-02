"""配置：内置默认值 + 可选 TOML 覆盖。

查找顺序（先找到先用）：
  1. --config 显式指定
  2. <项目目录>/config.toml
  3. ~/.config/dnsbypass/config.toml
字段全部可选，未提供即用默认值。优先级：CLI 参数 > 配置文件 > 内置默认。
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from . import PROJECT_DIR

DEFAULTS: dict[str, Any] = {
    # —— DoH 出口 ——
    # 默认 dns.google：本地被墙，但经代理可通（这正是本工具的前提）。
    "doh_url": "https://dns.google/dns-query",
    "timeout": 8.0,
    # DoH 瞬时失败（TLS 握手超时等）重试次数；仍失败才走明文兜底
    "doh_retries": 1,
    "ttl_cap": 300,
    "default_ttl": 30,
    "cache_max_entries": 4096,
    # 空 = 用环境里的 http_proxy/https_proxy；填了则覆盖（用于"真实代理入口"显式指定）。
    "upstream_proxy": "",
    # True = 即使 no_proxy 命中 DoH 域名也强制走代理（本地直连 DoH 是死的，必须走）。
    "force_proxy_for_doh": True,
    # False 时允许在完全没有代理的情况下直连 DoH（本环境里没有意义，留给别处用）。
    "require_proxy": True,

    # —— 本地监听 ——
    "listen_host": "127.0.0.1",
    "listen_port": 5353,        # 无需权限
    "bind_port": 53,            # bind 时要占的端口（需要权限，见 README）
    # 接管用的地址：WSL 镜像模式下 127.0.0.1:53 被 Windows 侧占着，
    # 发给它的包会被吞掉（绑定成功但收不到），所以换个环回地址。
    "bind_host": "127.0.0.2",

    # —— 接管 resolv.conf ——
    # 空 = 从原 resolv.conf 自动探测（排除 127.0.0.1），作为最后一位 nameserver 保命。
    "fallback_nameservers": [],
    "resolvconf_options": "timeout:2 attempts:1",
    # 空 = <项目目录>/state；也可用环境变量 DNSBYPASS_STATE_DIR 或全局参数 --state-dir 指定。
    # 相对路径一律以"代码所在目录"为基准，所以换个目录跑、换个工作目录跑都不会跑偏。
    "state_dir": "",

    # —— 审计 ——
    "canary_domains": [
        "www.google.com", "www.youtube.com", "x.com", "www.wikipedia.org",
        "www.reddit.com", "www.instagram.com", "www.dropbox.com",
        "www.nytimes.com", "signal.org", "www.bbc.com",
    ],
    # 对照组：预期"未被污染"的域名。若它们也大面积不一致，说明结论不可信。
    "control_domains": [
        "www.baidu.com", "www.taobao.com", "github.com", "www.qq.com",
    ],
    # 已知的投毒/合成地址（GFW 经典假 IP + 本机实测到的）
    "fake_ip_blacklist": [
        "31.13.92.37", "31.13.94.41", "104.244.42.197", "157.240.7.20",
        "157.240.12.36", "174.132.167.252", "69.171.235.22", "185.45.5.35",
        "199.59.148.96", "199.96.59.61", "50.87.93.246", "66.220.148.145",
        "108.160.165.8", "8.7.198.45", "59.24.3.173", "203.98.7.65",
        "243.185.187.39", "78.16.49.15", "46.82.174.68", "93.46.8.89",
        "37.61.54.158",
    ],
    # 这些域名一旦被污染，直接判"重度"
    "core_domains": ["www.google.com", "www.youtube.com", "www.wikipedia.org"],
    # 轻度污染的容忍条数（> 此数判重度）
    "light_max": 2,
}


class Config(dict):
    """轻量属性访问包装，避免到处写 config["x"]。"""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:  # pragma: no cover - 配置键拼错时给清晰报错
            raise AttributeError(f"配置项不存在: {name}") from exc

    def to_toml(self) -> str:
        """把生效配置打印成可直接另存为 config.toml 的文本。"""
        lines: list[str] = []
        for key, value in self.items():
            lines.append(f"{key} = {_toml_value(value)}")
        return "\n".join(lines) + "\n"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def candidate_paths(explicit: str | None = None) -> list[Path]:
    if explicit:
        return [Path(explicit).expanduser()]
    return [
        PROJECT_DIR / "config.toml",
        Path.home() / ".config" / "dnsbypass" / "config.toml",
    ]


def load(explicit: str | None = None) -> tuple[Config, Path | None]:
    """返回 (配置, 实际加载的文件或 None)。"""
    cfg = Config(DEFAULTS)
    used: Path | None = None
    for path in candidate_paths(explicit):
        if path.is_file():
            with path.open("rb") as fh:
                data = tomllib.load(fh)
            for key, value in data.items():
                cfg[key] = value
            used = path
            break
    return cfg, used


def state_dir(cfg: Config) -> Path:
    """解析状态目录：配置 > 环境变量 > <项目目录>/state。

    相对路径一律相对**代码所在目录**（PROJECT_DIR），而不是当前工作目录 ——
    这样 `cd / && /opt/dnsbypass/dnsbypass status` 与在项目目录里跑是同一份状态。
    """
    raw = str(cfg.get("state_dir") or "").strip()
    if not raw:
        raw = os.environ.get("DNSBYPASS_STATE_DIR", "").strip()
    path = Path(raw).expanduser() if raw else (PROJECT_DIR / "state")
    if not path.is_absolute():
        path = PROJECT_DIR / path
    path.mkdir(parents=True, exist_ok=True)
    return path


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}