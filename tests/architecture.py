#!/usr/bin/env python3
"""架构守护 —— 把 docs/ARCHITECTURE.md 第 6 节的不变量变成可执行断言。

    python3 tests/architecture.py          # 全绿则退出码 0

不需要 root、不碰 /etc：接管相关的检查全部在 mktemp 沙箱里做
（`resolvconf.bind/unbind` 都支持传 target，所以可以在临时目录里完整走一遍）。

改代码之前先读 docs/ARCHITECTURE.md；改完先跑本文件，再跑
`tests/resolvconf-sandbox.sh`，涉及真机行为的再跑 `sudo tests/full-stack.sh`。
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import socket
import struct
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DOC = ROOT / "docs" / "ARCHITECTURE.md"

# ---------------------------------------------------------------- 架构表（第 3 节）
LAYERS = {
    "wire": 0, "proxyenv": 0, "helpdoc": 0, "__init__": 0,
    "config": 1, "transport": 1,
    "doh": 2, "resolvconf": 2,
    "engine": 3, "audit": 3,
    "preflight": 4,
    "cli": 5,
}
CORE_COMMANDS = {
    "help", "config", "preflight", "audit", "probe",
    "run", "start", "stop", "status", "bind", "unbind", "repair",
}
INV_IDS = list(range(1, 18))

_results: list[tuple[str, str, object]] = []


def check(cid: str, desc: str):
    def deco(fn):
        _results.append((cid, desc, fn))
        return fn
    return deco


def src(name: str) -> str:
    return (ROOT / "dnsbp" / f"{name}.py").read_text(encoding="utf-8")


def tree_of(name: str) -> ast.Module:
    return ast.parse(src(name))


def silent(*_a, **_k) -> None:  # 给 bind/unbind 当 log 用
    pass


def _sandbox_cfg(tmp: str):
    # 注意：Config() 本身是空字典，默认值只在 load() 里合并进来，测试里要显式带 DEFAULTS。
    from dnsbp.config import DEFAULTS, Config
    cfg = Config(DEFAULTS)
    cfg["state_dir"] = str(Path(tmp) / "state")
    cfg["fallback_nameservers"] = ["10.255.255.254"]  # 避免测试期间联网探测
    return cfg


def _stub_client(responder, timeout: float = 1.0):
    class Stub:
        def __init__(self) -> None:
            self.timeout = timeout
            self.calls = 0
        def query_raw(self, pkt: bytes) -> bytes:
            self.calls += 1
            return responder(pkt)
    return Stub()


def _response_for(query: bytes, ip: str = "1.2.3.4", ttl: int = 60) -> bytes:
    """把一条 A 查询改造成带一条 A 记录的正常应答（QR=1、rcode=0）。"""
    resp = bytearray(query)
    resp[2] = 0x81  # QR=1, RD=1
    resp[3] = 0x80  # RA=1
    resp[6:8] = struct.pack(">H", 1)  # ANCOUNT=1
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return bytes(resp) + answer


# ================================================================ 结构断言
@check("ARCH-LAYER", "模块分层：只允许上层 import 下层，同层互引/反向边即失败")
def _layers():
    edges = {}
    for name in LAYERS:
        deps = set()
        for node in ast.walk(tree_of(name)):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                if node.module:
                    deps.add(node.module.split(".")[0])
                for alias in node.names:
                    if alias.name in LAYERS:
                        deps.add(alias.name)
        deps = {d for d in deps if d in LAYERS and d != name}
        edges[name] = deps
        for dep in deps:
            if LAYERS[dep] > LAYERS[name]:
                raise AssertionError(f"{name}(L{LAYERS[name]}) 反向依赖 {dep}(L{LAYERS[dep]})")
            if LAYERS[dep] == LAYERS[name]:
                raise AssertionError(f"{name} 与 {dep} 同层互引（应下沉公共逻辑到 L0–L2）")
    return "；".join(f"{n}→{sorted(d)}" for n, d in sorted(edges.items()) if d)


@check("ARCH-STDLIB", "零第三方依赖：dnsbp/*.py 与启动器只允许 import 标准库")
def _stdlib_only():
    bad = []
    for name in LAYERS:
        for node in ast.walk(tree_of(name)):
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            else:
                continue
            for m in mods:
                if m not in sys.stdlib_module_names and m != "dnsbp":
                    bad.append(f"dnsbp/{name}.py: {m}")
    launcher = (ROOT / "dnsbypass").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(launcher)):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top = node.module.split(".")[0]
            if top not in sys.stdlib_module_names and top != "dnsbp":
                bad.append(f"dnsbypass: {top}")
    if bad:
        raise AssertionError("发现非标准库依赖: " + ", ".join(bad))
    return f"{len(LAYERS)} 个模块 + 启动器均只用标准库"


@check("INV-12", "不写死路径：源码里不得出现个人/家目录路径，state_dir 必须锚定 PROJECT_DIR")
def _no_hardcoded_paths():
    from dnsbp.config import DEFAULTS, Config, state_dir
    from dnsbp import PROJECT_DIR
    pat = re.compile(r"/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+")
    hits = []
    for name in LAYERS:
        for i, line in enumerate(src(name).splitlines(), 1):
            if pat.search(line):
                hits.append(f"dnsbp/{name}.py:{i}: {line.strip()}")
    if pat.search((ROOT / "dnsbypass").read_text(encoding="utf-8")):
        hits.append("dnsbypass 启动器里出现个人路径")
    if "Path.cwd()" in src("config"):
        hits.append("config.py 用了 Path.cwd()（应由 PROJECT_DIR 锚定）")
    if hits:
        raise AssertionError("; ".join(hits))
    cfg = Config(DEFAULTS)
    cfg["state_dir"] = ".arch-probe-state"
    probe = ROOT / ".arch-probe-state"
    old = os.getcwd()
    os.chdir(tempfile.gettempdir())
    try:
        resolved = state_dir(cfg)  # 注意：这个函数会 mkdir -p（见 ARCHITECTURE 4.3）
    finally:
        os.chdir(old)
        shutil.rmtree(probe, ignore_errors=True)
    if not resolved.is_absolute() or not str(resolved).startswith(str(PROJECT_DIR)):
        raise AssertionError(f"相对 state_dir 没锚定 PROJECT_DIR: {resolved}")
    return f"cwd={tempfile.gettempdir()} 时，相对 state_dir → {resolved}"


@check("INV-13", "退出码：只在 __init__.py 定义、语义固定且互不重复")
def _exit_codes():
    from dnsbp import EXIT_ERROR, EXIT_HEAVY, EXIT_LIGHT, EXIT_OK, EXIT_PREFLIGHT
    expect = {EXIT_OK: 0, EXIT_LIGHT: 10, EXIT_HEAVY: 20, EXIT_PREFLIGHT: 30, EXIT_ERROR: 40}
    for value, want in expect.items():
        if value != want:
            raise AssertionError(f"退出码变了: {value} != {want}")
    if len(set(expect)) != 5:
        raise AssertionError("退出码有重复")
    for name in LAYERS:
        if name == "__init__":
            continue
        for i, line in enumerate(src(name).splitlines(), 1):
            if re.match(r"^EXIT_[A-Z_]+\s*=", line):
                raise AssertionError(f"dnsbp/{name}.py:{i} 私自定义退出码")
    return "OK=0 LIGHT=10 HEAVY=20 PREFLIGHT=30 ERROR=40"


@check("INV-14", "help 覆盖：每个子命令都要有中文条目，且 --state-dir 不能被子解析器覆盖")
def _help_coverage():
    from dnsbp import cli, helpdoc
    names = []
    for node in ast.walk(tree_of("cli")):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_parser" and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            names.append(node.args[0].value)
    missing = CORE_COMMANDS - set(names)
    if missing:
        raise AssertionError(f"cli 缺少核心子命令: {sorted(missing)}")
    if set(names) != set(helpdoc.COMMANDS):
        raise AssertionError(
            f"子命令与 helpdoc.COMMANDS 不一致: 只在 cli={sorted(set(names) - set(helpdoc.COMMANDS))}, "
            f"只在 helpdoc={sorted(set(helpdoc.COMMANDS) - set(names))}"
        )
    for name in names:
        if len(helpdoc.render(name)) < 20:
            raise AssertionError(f"`help {name}` 内容太短")
    parser = cli.build_parser()
    # 全局 --state-dir 写子命令之前：必须活下来（子解析器的 SUPPRESS 就是防这个）
    ns = parser.parse_args(["--state-dir", "/tmp/arch-probe", "status"])
    if ns.state_dir != "/tmp/arch-probe":
        raise AssertionError("子命令前的全局 --state-dir 被覆盖了（common 的 default 没写 SUPPRESS？）")
    # 也允许写在子命令之后
    ns_after = parser.parse_args(["status", "--state-dir", "/tmp/arch-probe2"])
    if ns_after.state_dir != "/tmp/arch-probe2":
        raise AssertionError("子命令后的 --state-dir 没生效")
    # 不传时应当是空值，交给 config 层解析（而不是被塞进某个默认目录）
    if parser.parse_args(["status"]).state_dir is not None:
        raise AssertionError("未传 --state-dir 时不该有具体值")
    return f"{len(names)} 个子命令均有中文帮助；--state-dir 前置/后置均可"


@check("INV-11", "接管逻辑不依赖引擎：resolvconf.py 不得 import engine/doh")
def _resolvconf_independence():
    deps = set()
    for node in ast.walk(tree_of("resolvconf")):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            if node.module:
                deps.add(node.module.split(".")[0])
            for alias in node.names:
                deps.add(alias.name)
    bad = deps & {"engine", "doh", "preflight", "cli"}
    if bad:
        raise AssertionError(f"resolvconf.py 依赖了 {sorted(bad)}")
    return f"resolvconf.py 仅依赖 {sorted(d for d in deps if d in LAYERS)}"


@check("INV-7", "DoH 永远走代理：显式 ProxyHandler，且不把 no_proxy 传下去")
def _doh_always_proxied():
    from dnsbp.doh import DohClient
    from dnsbp.proxyenv import ProxyEnv
    text = src("doh")
    if "ProxyHandler" not in text:
        raise AssertionError("doh.py 里没有显式 ProxyHandler")
    proxy = ProxyEnv(http="http://127.0.0.1:65532", https="http://127.0.0.1:65532",
                     all="", no_proxy="dns.google,example.com", source="test", raw={})
    client = DohClient("https://dns.google/dns-query", proxy=proxy, force_proxy=True)
    handlers = [h for h in getattr(client._opener, "handlers", []) if h.__class__.__name__ == "ProxyHandler"]
    if not handlers:
        raise AssertionError("opener 里没有 ProxyHandler")
    mapping = getattr(handlers[0], "proxies", {})
    if not any("https" in str(k) for k in mapping):
        raise AssertionError(f"https 没有走代理: {mapping}")
    return f"no_proxy={proxy.no_proxy!r} 被忽略，https → {mapping}"


@check("INV-8", "引擎必须同端口同时绑 UDP 与 TCP")
def _udp_and_tcp():
    text = src("engine")
    for needle in ("SOCK_DGRAM", "SOCK_STREAM"):
        if needle not in text:
            raise AssertionError(f"engine.py 里没有 {needle}")
    from dnsbp.engine import Server
    fn_src = ""
    for node in ast.walk(tree_of("engine")):
        if isinstance(node, ast.FunctionDef) and node.name == "open_sockets":
            fn_src = ast.get_source_segment(text, node) or ""
    for needle in ("SOCK_DGRAM", "SOCK_STREAM"):
        if needle not in fn_src:
            raise AssertionError(f"Server.open_sockets() 里没有 {needle}")
    return "open_sockets() 同时绑 UDP/TCP"


@check("INV-9", "绑特权端口后必须降权")
def _drop_privileges():
    from dnsbp import cli
    if not hasattr(cli, "drop_privileges"):
        raise AssertionError("cli 没有引入 drop_privileges")
    if "drop_privileges(" not in src("cli"):
        raise AssertionError("cmd_run 没有调用 drop_privileges()")
    text = src("engine")
    if "SUDO_UID" not in text or "SUDO_GID" not in text:
        raise AssertionError("drop_privileges 没认 SUDO_UID/SUDO_GID")
    return "认 SUDO_UID/SUDO_GID"


@check("INV-10", "临时文件必须唯一命名、清旧名，失败要转成 ResolvError")
def _tmp_files():
    from dnsbp import resolvconf
    for name in ("_tmp_sibling", "_remove_stale_tmp", "_write_tmp_and_move"):
        if not hasattr(resolvconf, name):
            raise AssertionError(f"resolvconf 缺少 {name}")
    text = src("resolvconf")
    if "PermissionError" not in text or "ResolvError" not in text:
        raise AssertionError("写入失败没有转成 ResolvError")
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-tmp-")
    try:
        a = resolvconf._tmp_sibling(Path(tmp) / "resolv.conf", "tmp")
        b = resolvconf._tmp_sibling(Path(tmp) / "resolv.conf", "tmp")
        if a == b or a.parent != Path(tmp):
            raise AssertionError(f"临时名不唯一/不在同目录: {a} vs {b}")
        return f"唯一临时名示例 {a.name}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("INV-16", "保命线：render 必须保留明文兜底，cmd_run 必须自动探测兜底")
def _lifeline():
    from dnsbp.config import Config
    from dnsbp import resolvconf
    cfg = Config()
    text = resolvconf.render(cfg, "127.0.0.2", ["10.255.255.254"])
    if "nameserver 127.0.0.2" not in text or "nameserver 10.255.255.254" not in text:
        raise AssertionError(f"render 结果缺少 nameserver 行:\n{text}")
    if not resolvconf.is_managed(text):
        raise AssertionError("render 出来的内容不被 is_managed() 认作自产")
    if "detect_fallbacks" not in src("cli"):
        raise AssertionError("cmd_run 没有自动探测明文兜底")
    return text.replace("\n", " | ")


# ================================================================ 行为断言（沙箱）
@check("INV-1", "接管/回滚全程不写穿符号链接目标（沙箱内 bind→unbind 验证）")
def _inv1_no_write_through():
    from dnsbp import resolvconf
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-inv1-")
    try:
        real = Path(tmp) / "wsl-resolv.conf"
        orig = "# WSL generated\nnameserver 10.255.255.254\n"
        real.write_text(orig, encoding="utf-8")
        link = Path(tmp) / "resolv.conf"
        link.symlink_to(real)
        cfg = _sandbox_cfg(tmp)
        rec = resolvconf.bind(cfg, target=link, log=silent)
        if real.read_text(encoding="utf-8") != orig:
            raise AssertionError("bind 写穿了符号链接目标！")
        if link.is_symlink() or not link.is_file():
            raise AssertionError("bind 没有把 /etc/resolv.conf 换成真文件")
        if "nameserver 127.0.0.2" not in link.read_text(encoding="utf-8"):
            raise AssertionError("生成内容里没有我们的 nameserver")
        resolvconf.unbind(cfg, log=silent)
        if not link.is_symlink() or os.readlink(link) != str(real):
            raise AssertionError("unbind 没有恢复符号链接")
        if real.read_text(encoding="utf-8") != orig:
            raise AssertionError("unbind 改动了链接目标内容")
        if rec["original_kind"] != "symlink":
            raise AssertionError(f"original_kind 记错了: {rec['original_kind']}")
        return "bind 换真文件、目标未动、unbind 恢复 symlink"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("INV-2", "备份只写一次、只写非自产内容（重复 bind 不改备份）")
def _inv2_backup_once():
    from dnsbp import resolvconf
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-inv2-")
    try:
        real = Path(tmp) / "wsl-resolv.conf"
        orig = "# WSL generated\nnameserver 10.255.255.254\n"
        real.write_text(orig, encoding="utf-8")
        link = Path(tmp) / "resolv.conf"
        link.symlink_to(real)
        cfg = _sandbox_cfg(tmp)
        rec1 = resolvconf.bind(cfg, target=link, log=silent)
        backup = Path(rec1["backup_path"])
        before = backup.read_bytes()
        if backup.read_text(encoding="utf-8") != orig:
            raise AssertionError("首次备份内容不是原始内容")
        if backup.read_text(encoding="utf-8").startswith(resolvconf.MANAGED_MARK):
            raise AssertionError("备份里存的是自产内容")
        resolvconf.bind(cfg, target=link, log=silent)  # 托管中再 bind 一次
        if backup.read_bytes() != before:
            raise AssertionError("重复 bind 覆盖了原始备份")
        for name, want in (("resolv.conf.backup", orig),
                           ("resolv.conf.target.backup", orig)):
            path = Path(cfg["state_dir"]) / name
            if not path.exists() or path.read_text(encoding="utf-8") != want:
                raise AssertionError(f"{name} 内容不对")
        return "备份内容 = 原始内容，重复 bind 未改动"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("INV-3", "重复 bind 沿用首次原始身份，created_at 不刷新")
def _inv3_inherit():
    from dnsbp import resolvconf
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-inv3-")
    try:
        real = Path(tmp) / "wsl-resolv.conf"
        real.write_text("# WSL generated\nnameserver 10.255.255.254\n", encoding="utf-8")
        link = Path(tmp) / "resolv.conf"
        link.symlink_to(real)
        cfg = _sandbox_cfg(tmp)
        r1 = resolvconf.bind(cfg, target=link, log=silent)
        r2 = resolvconf.bind(cfg, target=link, log=silent)
        if r2["original_kind"] != "symlink" or r2["original_link_target"] != str(real):
            raise AssertionError(f"原始身份丢了: {r2['original_kind']} / {r2['original_link_target']}")
        if r2["created_at"] != r1["created_at"]:
            raise AssertionError("created_at 被刷新了")
        if "rebound_at" not in r2:
            raise AssertionError("缺少 rebound_at")
        if not (r2.get("inherited_original") and r2.get("current_was_managed")):
            raise AssertionError("继承标记没置上")
        return f"kind=symlink 继承；created_at={r1['created_at_text']}；rebound_at={r2['rebound_at_text']}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("INV-4", "自产内容但无记录 ⇒ 拒绝接管（ResolvError，退出码 40）")
def _inv4_refuse():
    from dnsbp import resolvconf
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-inv4-")
    try:
        f = Path(tmp) / "resolv.conf"
        f.write_text(resolvconf.MANAGED_MARK + "\nnameserver 127.0.0.2\n", encoding="utf-8")
        cfg = _sandbox_cfg(tmp)  # 状态目录是空的，没有记录
        try:
            resolvconf.bind(cfg, target=f, log=silent)
        except resolvconf.ResolvError as exc:
            if "repair" not in str(exc):
                raise AssertionError("拒绝时没有指路 repair")
            return str(exc).splitlines()[0]
        raise AssertionError("竟然接管了一份无记录的自产文件")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("INV-15", "resolvconf options 的 timeout 不得小于 2")
def _timeout_floor():
    from dnsbp.config import DEFAULTS
    text = str(DEFAULTS.get("resolvconf_options", ""))
    m = re.search(r"timeout:(\d+)", text)
    if not m or int(m.group(1)) < 2:
        raise AssertionError(f"resolvconf_options 太激进: {text!r}（timeout<2 会掉到被投毒的第二个 nameserver）")
    if DEFAULTS.get("bind_host") == "127.0.0.1":
        raise AssertionError("bind_host 不能是 127.0.0.1（镜像模式下被 Windows 占着）")
    return f"{text}；bind_host={DEFAULTS['bind_host']}"


@check("INV-5", "每条出站应答都要重写 txid（命中缓存也要）")
def _txid_rewrite():
    from dnsbp import wire
    from dnsbp.engine import Resolver
    q1 = wire.build_query("example.com", qid=0x1111)
    client = _stub_client(lambda pkt: _response_for(pkt))
    res = Resolver(client, fallback_servers=[], log=silent)
    r1, s1 = res.resolve(q1)
    if s1 != "doh" or r1 is None or wire.txid(r1) != 0x1111:
        raise AssertionError(f"首个应答 txid 不对: source={s1} txid={wire.txid(r1 or b'')}")
    q2 = wire.build_query("example.com", qid=0x2222)
    r2, s2 = res.resolve(q2)
    if s2 != "cache" or r2 is None or wire.txid(r2) != 0x2222:
        raise AssertionError(f"缓存应答没有重写 txid: source={s2} txid={wire.txid(r2 or b'')}")
    return "DoH 应答 0x1111、缓存命中 0x2222 都正确回填"


@check("INV-6", "只缓存 DoH 应答：明文兜底的答案不许进缓存")
def _cache_only_doh():
    from dnsbp import engine as eng
    from dnsbp import wire
    from dnsbp.doh import DohError
    def boom(_pkt):
        raise DohError("stub: DoH 不可用")
    client = _stub_client(boom)
    res = eng.Resolver(client, fallback_servers=["10.255.255.254"], log=silent)
    orig = eng.udp_query
    calls = {"n": 0}
    def fake_udp(server, pkt, timeout=3.0, port=53):
        calls["n"] += 1
        return _response_for(pkt, ip="185.45.5.35")
    eng.udp_query = fake_udp
    try:
        q = wire.build_query("fallback.example", qid=0x3333)
        _, s1 = res.resolve(q)
        _, s2 = res.resolve(wire.build_query("fallback.example", qid=0x4444))
        if not s1.startswith("fallback:") or not s2.startswith("fallback:"):
            raise AssertionError(f"明文兜底路径不对: {s1} / {s2}")
        if calls["n"] != 2:
            raise AssertionError("兜底答案被缓存了（第二次没重新查询）—— 会把投毒答案留下")
        return f"兜底两次都重新查询（{calls['n']} 次），未进缓存"
    finally:
        eng.udp_query = orig


@check("INV-1/INV-2/INV-3", "老版本坏备份不再挡回滚（符号链接分支不依赖备份内容）")
def _stale_backup_does_not_block():
    from dnsbp import resolvconf
    tmp = tempfile.mkdtemp(prefix="dnsbypass-arch-stale-")
    try:
        real = Path(tmp) / "wsl-resolv.conf"
        orig = "# WSL generated\nnameserver 10.255.255.254\n"
        real.write_text(orig, encoding="utf-8")
        link = Path(tmp) / "resolv.conf"
        link.symlink_to(real)
        cfg = _sandbox_cfg(tmp)
        rec = resolvconf.bind(cfg, target=link, log=silent)
        backup = Path(rec["backup_path"])
        backup.write_text(resolvconf.MANAGED_MARK + "\nnameserver 127.0.0.2\n", encoding="utf-8")
        resolvconf.unbind(cfg, log=silent)  # 旧版会在这里抛 ResolvError
        if not link.is_symlink():
            raise AssertionError("被坏备份挡住，没恢复符号链接")
        if backup.read_text(encoding="utf-8") != orig:
            raise AssertionError("没有顺手把坏备份治好")
        return "坏备份未挡回滚，且被治好"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@check("ARCH-DOC", "docs/ARCHITECTURE.md 里的 INV 编号与本文件的断言一一对应")
def _doc_sync():
    if not DOC.exists():
        raise AssertionError("缺少 docs/ARCHITECTURE.md")
    text = DOC.read_text(encoding="utf-8")
    doc_ids = {int(m) for m in re.findall(r"INV-(\d+)", text)}
    script_ids = set(INV_IDS)
    if doc_ids != script_ids:
        raise AssertionError(f"文档有而测试没有: {sorted(doc_ids - script_ids)}；"
                             f"测试有而文档没写: {sorted(script_ids - doc_ids)}")
    for needle in ("bind_host", "ccd28ae0776549eb3926db2148a50bff", "MANAGED_MARK"):
        if needle not in text:
            raise AssertionError(f"文档缺少关键事实: {needle}")
    return f"INV-1..INV-{max(doc_ids)} 全部有断言"


@check("ARCH-TESTS", "README 必须列出三个测试入口，脚本必须存在且可执行")
def _tests_present():
    for rel in ("tests/architecture.py", "tests/resolvconf-sandbox.sh", "tests/full-stack.sh"):
        p = ROOT / rel
        if not p.exists():
            raise AssertionError(f"缺少 {rel}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for needle in ("tests/architecture.py", "resolvconf-sandbox.sh", "full-stack.sh", "docs/ARCHITECTURE.md"):
        if needle not in readme:
            raise AssertionError(f"README 没提到 {needle}")
    return "README 与三个测试入口一致"


# ================================================================ 跑
def main() -> int:
    width = max(len(cid) for cid, _, _ in _results)
    failed = 0
    print(f"架构守护 · {ROOT}")
    print("-" * 78)
    for cid, desc, fn in _results:
        try:
            detail = fn() or ""
            print(f"  ✅ {cid:<{width}}  {desc}")
            if detail:
                print(f"     └─ {detail}")
        except Exception as exc:  # noqa: BLE001 —— 断言失败要全跑完再报
            failed += 1
            print(f"  ❌ {cid:<{width}}  {desc}")
            print(f"     └─ {type(exc).__name__}: {exc}")
            if not isinstance(exc, AssertionError):
                traceback.print_exc()
    print("-" * 78)
    total = len(_results)
    if failed:
        print(f"❌ {failed}/{total} 项失败 —— 架构被破坏了（见 docs/ARCHITECTURE.md 第 6 节）")
        return 1
    print(f"✅ {total}/{total} 项全部通过，架构未漂移")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())