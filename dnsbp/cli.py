"""命令行入口：体检 → 审计 → 起引擎 → 接管 / 回滚。

设计原则：
  * 每个子命令都能单独用；`audit` 与 `preflight` 只读，不写任何系统文件。
  * 只有 `bind` / `unbind` 会动 `/etc/resolv.conf`，而且必带记录与回滚。
  * 退出码有意义：0 干净、10 轻微、20 污染/重污染、30 前置不通、40 出错。
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import EXIT_ERROR, EXIT_OK, EXIT_PREFLIGHT, helpdoc, resolvconf, wire
from .audit import _blacklisted as audit_is_blacklisted
from .audit import audit, probe_doh, write_report
from .config import Config, load, state_dir
from .doh import DohClient, DohError
from .engine import EngineError, Resolver, Server, drop_privileges, process_alive
from .preflight import run as run_preflight
from .proxyenv import effective_proxy, mask, recover_from_processes, snapshot
from .transport import PlainDnsError, ask_a

PROGRAM = "dnsbypass"


# ---------------------------------------------------------------- 组装

def loginfo(message: str) -> None:
    """诊断信息一律走 stderr，保证 stdout 只出数据（--json 可被管道消费）。"""
    print(message, file=sys.stderr)


def ensure_proxy(cfg: Config, args, log=loginfo) -> str:
    """保证引擎出站有代理可用。

    顺序：--proxy 参数 > config 的 upstream_proxy > 当前环境。
    若我们在 sudo 之下、环境已被 env_reset 清空，则尝试从**调用者身份的其它进程**
    里把代理捡回来并写回本进程环境（子进程会继承）。捡不到就明确提示。
    """
    env = snapshot()
    override = (getattr(args, "proxy", None) or "").strip()
    if override:
        cfg["upstream_proxy"] = override
        log(f"[{PROGRAM}] 代理：使用 --proxy {mask(override)}")
        return override
    if cfg.get("upstream_proxy"):
        log(f"[{PROGRAM}] 代理：使用 config.toml 的 upstream_proxy {mask(str(cfg['upstream_proxy']))}")
        return str(cfg["upstream_proxy"])
    if env.has_any():
        return ""
    if os.environ.get("SUDO_UID"):
        found = recover_from_processes()
        if found.has_any():
            shown = mask(found.http or found.https or found.all)
            for key, value in (
                ("http_proxy", found.http), ("HTTP_PROXY", found.http),
                ("https_proxy", found.https), ("HTTPS_PROXY", found.https),
                ("all_proxy", found.all), ("ALL_PROXY", found.all),
                ("no_proxy", found.no_proxy), ("NO_PROXY", found.no_proxy),
            ):
                if value:
                    os.environ[key] = value
            log(f"[{PROGRAM}] 代理：sudo 的 env_reset 丢掉了它，已从 {found.source} 找回 {shown}")
            return shown
        log(f"[{PROGRAM}] 代理：sudo 环境里没有，也没能从调用者进程捡回来 "
            f"→ 用 --proxy http://127.0.0.1:65532 或在 config.toml 写 upstream_proxy")
    return ""


def build_client(cfg: Config, args: argparse.Namespace) -> DohClient:
    url = getattr(args, "doh", None) or cfg["doh_url"]
    timeout = float(getattr(args, "timeout", None) or cfg["timeout"])
    proxy = effective_proxy(snapshot(), cfg.get("upstream_proxy") or "")
    return DohClient(
        url=url,
        timeout=timeout,
        proxy=proxy,
        force_proxy=bool(cfg.get("force_proxy_for_doh", True)),
    )


def build_resolver(cfg: Config, client: DohClient, log=loginfo) -> Resolver:
    return Resolver(
        client=client,
        fallback_servers=list(cfg.get("fallback_nameservers") or []),
        ttl_cap=int(cfg["ttl_cap"]),
        default_ttl=int(cfg["default_ttl"]),
        cache_max=int(cfg["cache_max_entries"]),
        doh_retries=int(cfg.get("doh_retries", 1)),
        log=log,
    )


def emit(args: argparse.Namespace, payload: dict, text: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(text)


def tail_file(path: Path, lines: int = 14) -> str:
    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])


# ---------------------------------------------------------------- 子命令

def cmd_help(cfg: Config, args) -> int:
    text = helpdoc.render(getattr(args, "topic", None))
    emit(args, {"topic": getattr(args, "topic", None) or "overview", "text": text}, text)
    return EXIT_OK


def cmd_config(cfg: Config, args) -> int:
    data = {
        "config_path": str(getattr(cfg, "source_path", "") or "(内置默认)"),
        "state_dir": str(state_dir(cfg)),
        "config": dict(cfg),
        "proxy": snapshot().as_dict() if hasattr(snapshot(), "as_dict") else {
            "http": snapshot().http, "https": snapshot().https,
            "all": snapshot().all, "no_proxy": snapshot().no_proxy,
            "source": snapshot().source,
        },
        "config_toml": cfg.to_toml(),
    }
    shown = Config(cfg)
    shown["state_dir"] = str(state_dir(cfg))
    emit(args, data, shown.to_toml())
    return EXIT_OK


def cmd_preflight(cfg: Config, args) -> int:
    ensure_proxy(cfg, args)
    client = build_client(cfg, args)
    report = run_preflight(cfg, client, live_probe=not args.no_probe)
    emit(args, report.to_dict(), report.render())
    if not report.ok:
        print(f"\n{PROGRAM}: 前置检查未通过（{len(report.fatal)} 项致命）", file=sys.stderr)
        return EXIT_PREFLIGHT
    return EXIT_OK


def cmd_audit(cfg: Config, args) -> int:
    ensure_proxy(cfg, args)
    client = build_client(cfg, args)
    domains = [d.strip() for d in (args.domains or "").split(",") if d.strip()]
    report = audit(cfg, client, user_domains=domains, log=loginfo)
    text = report.render()
    payload = report.to_dict()
    if not report.doh_ok:
        emit(args, payload, text)
        return report.exit_code
    path = write_report(report, cfg)
    text += f"\n报告: {path}"
    if report.should_bind:
        text += f"\n建议: sudo {PROGRAM} bind   # 接管本机解析（可 unbind 回滚）"
    emit(args, payload, text)
    return report.exit_code


def cmd_probe(cfg: Config, args) -> int:
    ensure_proxy(cfg, args)
    client = build_client(cfg, args)
    domains = [d.strip() for d in (args.domains or "www.google.com").split(",") if d.strip()]
    from .audit import local_resolver

    target = local_resolver(cfg, log=lambda *_: None)
    print(f"DoH: {client.url}  |  明文样本: {target}")
    worst = EXIT_OK
    for domain in domains:
        try:
            result = client.query_name(domain)
            doh_answers = result.answers()
            doh_text = f"{','.join(doh_answers) or '-'} ({result.elapsed_ms:.0f}ms)"
        except DohError as exc:
            doh_answers, doh_text = [], f"失败: {exc}"
            worst = max(worst, EXIT_PREFLIGHT)
        try:
            local_answers = ask_a(target, domain, timeout=min(cfg["timeout"], 5.0))
            local_text = f"{','.join(local_answers) or '-'}"
        except PlainDnsError as exc:
            local_answers, local_text = [], f"失败: {exc}"
        fake = [ip for ip in local_answers if wire.is_fake_ip(ip) or audit_is_blacklisted(ip, cfg.get("fake_ip_blacklist") or [])]
        same = bool(doh_answers) and set(doh_answers) == set(local_answers)
        if fake:
            mark = "⚠"
        elif same:
            mark = "✓"
        else:
            mark = "~"   # 不同但都可能是真值（anycast / CDN 就近节点）
        hint = "  ⚠假IP:" + ",".join(fake) if fake else ("" if same else "  (与 DoH 不同，可能只是就近节点)")
        print(f"  {mark} {domain:<26} doh={doh_text:<44} local={local_text}{hint}")
    return worst


def cmd_run(cfg: Config, args) -> int:
    ensure_proxy(cfg, args)
    client = build_client(cfg, args)
    port = int(args.port or cfg["listen_port"])
    # 53 走 bind_host：镜像模式下 127.0.0.1:53 被 Windows 侧占用，包收不到。
    default_host = cfg["bind_host"] if port == int(cfg["bind_port"]) else cfg["listen_host"]
    host = args.host or default_host
    cfg["listen_host"], cfg["listen_port"] = host, port
    if args.fallback:
        cfg["fallback_nameservers"] = [s.strip() for s in args.fallback.split(",") if s.strip()]
    if not cfg["fallback_nameservers"]:
        # 引擎自己的保命线：DoH 全挂时还能明文解析（bind 写进 resolv.conf 的是同一个清单）
        cfg["fallback_nameservers"] = resolvconf.detect_fallbacks(cfg, host)
    if cfg["fallback_nameservers"]:
        print(f"[{PROGRAM}] 明文兜底: {', '.join(cfg['fallback_nameservers'])}", file=sys.stderr)
    else:
        print(f"[{PROGRAM}] 警告: 没有可用兜底解析器，DoH 挂了就真的解析不了", file=sys.stderr)

    if not args.no_preflight:
        report = run_preflight(cfg, client, live_probe=not args.no_probe)
        print(report.render(), file=sys.stderr)
        if not report.ok and not args.force:
            print(f"{PROGRAM}: 前置检查未通过，用 --force 可强行启动", file=sys.stderr)
            return EXIT_PREFLIGHT

    resolver = build_resolver(cfg, client)
    state_path = state_dir(cfg) / "engine.json"
    server = Server(resolver, host=host, port=port, state_path=state_path)

    def _term(_signum, _frame):
        server.stop()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    try:
        server.open_sockets()
    except EngineError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        if port == 53 and os.geteuid() != 0:
            print(f"提示: sudo {PROGRAM} run --port 53   # sudo 会清掉代理，"
                  f"必要时加 --proxy http://127.0.0.1:65532", file=sys.stderr)
        return EXIT_ERROR
    note = drop_privileges()
    if note:
        print(f"[{PROGRAM}] {note}", file=sys.stderr)
    os.environ.setdefault("DNSBYPASS_ENGINE", "1")
    server.serve_forever()
    return EXIT_OK


def cmd_start(cfg: Config, args) -> int:
    ensure_proxy(cfg, args)
    state_path = state_dir(cfg) / "engine.json"
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if data.get("status") == "running" and process_alive(int(data.get("pid") or 0)):
                print(f"{PROGRAM}: 已在运行（pid={data['pid']}），先 stop", file=sys.stderr)
                return EXIT_ERROR
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    log_path = state_dir(cfg) / "engine.log"
    cmd = [sys.executable, "-u", "-m", "dnsbp.cli"]
    # 状态目录用绝对路径传给子进程：子进程的 cwd 可能与父进程不同，
    # 不显式给的话 engine.json/engine.log 会落到别处，status 就看不见它了。
    cmd += ["--state-dir", str(state_dir(cfg))]
    cmd += ["run"]
    if getattr(cfg, "source_path", ""):
        cmd += ["--config", str(cfg.source_path)]
    if args.port:
        cmd += ["--port", str(args.port)]
    if args.doh:
        cmd += ["--doh", args.doh]
    if cfg.get("upstream_proxy"):
        # --proxy / config.toml 的 upstream_proxy 必须显式传给子进程：
        # 只写进本进程的 cfg 不够，子进程是全新进程，拿不到那份配置之外的意图。
        cmd += ["--proxy", str(cfg["upstream_proxy"])]
    if args.fallback:
        cmd += ["--fallback", args.fallback]
    if args.no_probe:
        cmd += ["--no-probe"]
    if args.no_preflight:
        cmd += ["--no-preflight"]
    if args.force:
        cmd += ["--force"]
    env = dict(os.environ)
    # sudo 的 env_reset 会吃掉代理变量：ensure_proxy 已经把（找回/指定的）代理写进
    # os.environ，这里显式传给子进程，保证引擎出站那一跳一定走代理。
    for key in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
                "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n--- start {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        log.flush()
        proc = subprocess.Popen(
            cmd, cwd=str(Path(__file__).resolve().parent.parent),
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=env, start_new_session=True,
        )
    deadline = time.time() + float(args.wait)
    while time.time() < deadline:
        if proc.poll() is not None:
            print(f"{PROGRAM}: 启动失败（退出码 {proc.returncode}）；{log_path} 尾部：\n{tail_file(log_path)}",
                  file=sys.stderr)
            return EXIT_ERROR
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if data.get("status") == "running" and process_alive(int(data.get("pid") or 0)):
                print(f"{PROGRAM}: 已启动 pid={data['pid']} 监听 {data['host']}:{data['port']} 日志 {log_path}")
                return EXIT_OK
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.15)
    alive = proc.poll() is None
    print(f"{PROGRAM}: 等待启动超时（{args.wait:g}s，子进程{'仍在跑' if alive else '已退出'}）；"
          f"{log_path} 尾部：\n{tail_file(log_path)}", file=sys.stderr)
    if alive:
        print(f"提示: 加大 --wait，或先 {PROGRAM} stop", file=sys.stderr)
    return EXIT_ERROR


def cmd_stop(cfg: Config, args) -> int:
    state_path = state_dir(cfg) / "engine.json"
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"{PROGRAM}: 没有运行记录", file=sys.stderr)
        return EXIT_ERROR
    pid = int(data.get("pid") or 0)
    if not process_alive(pid):
        print(f"{PROGRAM}: pid={pid} 已不在（状态文件残留）")
        return EXIT_OK
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"{PROGRAM}: 发送 SIGTERM 失败: {exc}", file=sys.stderr)
        return EXIT_ERROR
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not process_alive(pid):
            print(f"{PROGRAM}: 已停止 pid={pid}")
            return EXIT_OK
        time.sleep(0.1)
    print(f"{PROGRAM}: pid={pid} 5 秒内未退出，可 kill -9 {pid}", file=sys.stderr)
    return EXIT_ERROR


def cmd_status(cfg: Config, args) -> int:
    state_path = state_dir(cfg) / "engine.json"
    view = resolvconf.inspect()
    payload = {"resolvconf": view.as_dict()}
    lines = [
        f"resolv.conf : {view.path}" + (f" → {view.link_target}" if view.is_symlink else "")
        + f"  nameserver={','.join(view.nameservers) or 'none'} 可写={view.writable}"
        + ("  ⚠ systemd-resolved stub" if view.stub_resolved else ""),
    ]
    host, port = cfg["listen_host"], cfg["listen_port"]
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        host, port = data.get("host", host), int(data.get("port", port))
        pid = int(data.get("pid") or 0)
        alive = process_alive(pid)
        payload["engine"] = data
        payload["engine_alive"] = alive
        lines.append(
            f"引擎       : {data.get('status')} pid={pid} {'存活' if alive else '不存在'}"
            f" {host}:{port} → {data.get('doh_url')}"
        )
        stats = data.get("stats") or {}
        if stats:
            lines.append("统计       : " + " ".join(f"{k}={v}" for k, v in stats.items())
                         + f" cache={data.get('cache_entries')}")
    except (OSError, json.JSONDecodeError):
        payload["engine"] = None
        lines.append("引擎       : 无状态文件（没起过或已清理）")

    from .preflight import port_probe

    ok, detail = port_probe(host, port)
    payload["port_free"] = ok
    engine_alive = bool(payload.get("engine_alive"))
    if not ok and engine_alive:
        detail += "（被本引擎占用，属正常）"
    lines.append(f"端口探测   : {detail}")
    record = resolvconf.load_record(cfg)
    payload["bind_record"] = record
    if record:
        target = record.get("original_link_target") or ""
        lines.append(f"绑定记录   : {record.get('status')}（原形态 {record.get('original_kind')}"
                     f"{' → ' + target if target else ''}）")
    else:
        lines.append("绑定记录   : 无（没 bind 过，或状态目录被换过）")
    backup = Path(record["backup_path"]) if record and record.get("backup_path") else state_dir(cfg) / resolvconf.BACKUP_NAME
    if backup.exists():
        backup_text = backup.read_text(encoding="utf-8", errors="replace")
        payload["backup_path"] = str(backup)
        payload["backup_usable"] = not resolvconf.is_managed(backup_text)
        lines.append(f"原始备份   : {backup} "
                     + ("可用" if payload["backup_usable"]
                        else "⚠ 内容是自产的（旧版缺陷），回滚请用 repair"))
    pointing = view.nameservers[:1] == [cfg["bind_host"]]
    payload["resolv_points_to_engine"] = pointing
    if pointing:
        lines.append("接管状态   : " + ("已指向本引擎" if engine_alive else
                     "⚠ 指向本引擎，但引擎没在跑（查询会落到第二个 nameserver：明文、可能被投毒）"))
    else:
        lines.append("接管状态   : 未接管（resolv.conf 指向别处）")
    emit(args, payload, "\n".join(lines))
    return EXIT_OK


def cmd_bind(cfg: Config, args) -> int:
    target = Path(args.target) if args.target else resolvconf.RESOLV_CONF
    try:
        record = resolvconf.bind(cfg, target=target, dry_run=args.dry_run)
    except resolvconf.ResolvError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        if os.geteuid() != 0:
            print(f"提示: sudo -E {PROGRAM} bind", file=sys.stderr)
        return EXIT_ERROR
    payload = {"record": record}
    text = json.dumps(record, ensure_ascii=False, indent=2)
    emit(args, payload, text)
    return EXIT_OK


def cmd_unbind(cfg: Config, args) -> int:
    try:
        result = resolvconf.unbind(cfg, dry_run=args.dry_run,
                                   target=Path(args.target) if args.target else None)
    except resolvconf.ResolvError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    emit(args, result, json.dumps({k: v for k, v in result.items()}, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_repair(cfg: Config, args) -> int:
    try:
        result = resolvconf.repair(
            cfg,
            target=Path(args.target) if args.target else resolvconf.RESOLV_CONF,
            real=Path(args.real) if args.real else None,
            nameserver=args.nameserver,
            dry_run=args.dry_run,
        )
    except resolvconf.ResolvError as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    emit(args, {"result": result}, json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


# ---------------------------------------------------------------- 入口

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="本机 DoH 接管工具：审计 DNS 污染 → 起 DoH 转发 → 接管 /etc/resolv.conf（可回滚）"
                    "；用例 `dnsbypass help`",
        epilog="看详细中文说明：dnsbypass help  /  dnsbypass help <命令>",
    )
    parser.add_argument("--config", help="显式指定 config.toml")
    parser.add_argument("--state-dir", help="状态目录（放运行状态/日志/备份；也可用 DNSBYPASS_STATE_DIR）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出（便于脚本消费）")
    # 让 --state-dir 也能写在子命令后面（argparse 默认只认子命令之前的位置）
    common = argparse.ArgumentParser(add_help=False)
    # default=SUPPRESS 很关键：子解析器默认值会在解析子命令时把全局 --state-dir 覆盖成 None
    common.add_argument("--state-dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("help", parents=[common], help="中文帮助：dnsbypass help [命令]")
    p.add_argument("topic", nargs="?", help="命令名（config/preflight/audit/...）；省略看总览")
    p.set_defaults(func=cmd_help)

    p = sub.add_parser("config", parents=[common], help="显示生效配置与来源")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("preflight", parents=[common], help="启动前体检（只读）")
    p.add_argument("--proxy", help="出站代理，如 http://127.0.0.1:65532（sudo 下必给）")
    p.add_argument("--doh", help="覆盖 DoH 端点")
    p.add_argument("--timeout", type=float)
    p.add_argument("--no-probe", action="store_true", help="跳过真实 DoH 探测")
    p.set_defaults(func=cmd_preflight)

    p = sub.add_parser("audit", parents=[common], help="污染审计（只读；退出码分级）")
    p.add_argument("--proxy", help="出站代理（sudo 下必给）")
    p.add_argument("--doh", help="覆盖 DoH 端点")
    p.add_argument("--timeout", type=float)
    p.add_argument("--domains", help="额外审计的域名，逗号分隔")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("probe", parents=[common], help="对比单个域名的 DoH 真值与明文结果")
    p.add_argument("--proxy", help="出站代理（sudo 下必给）")
    p.add_argument("--domains", help="域名，逗号分隔（默认 www.google.com）")
    p.add_argument("--doh", help="覆盖 DoH 端点")
    p.add_argument("--timeout", type=float)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("run", parents=[common], help="前台启动转发引擎（UDP+TCP）")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--proxy", help="出站代理（sudo 下必给）")
    p.add_argument("--doh")
    p.add_argument("--timeout", type=float)
    p.add_argument("--fallback", help="明文兜底解析器，逗号分隔")
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--no-preflight", action="store_true")
    p.add_argument("--force", action="store_true", help="前置检查失败也启动")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("start", parents=[common], help="后台启动转发引擎")
    p.add_argument("--port", type=int)
    p.add_argument("--proxy", help="出站代理（sudo 下必给；也可写进 config.toml）")
    p.add_argument("--doh")
    p.add_argument("--fallback")
    p.add_argument("--wait", type=float, default=25.0)
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--no-preflight", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", parents=[common], help="停止后台引擎")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("status", parents=[common], help="查看引擎与 resolv.conf 状态")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("bind", parents=[common], help="接管 /etc/resolv.conf（需 root；默认会先备份并记录）")
    p.add_argument("--target", help="改写这个文件而不是 /etc/resolv.conf（自测用）")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_bind)

    p = sub.add_parser("unbind", parents=[common], help="按记录回滚 /etc/resolv.conf")
    p.add_argument("--target")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_unbind)

    p = sub.add_parser("repair", parents=[common],
                       help="把 resolv.conf 恢复成 WSL 原始态（记录/备份损坏时的救命命令）")
    p.add_argument("--target", help="要恢复的路径（默认 /etc/resolv.conf）")
    p.add_argument("--real", help="符号链接的目标文件（默认按记录/惯例推断，WSL 下是 /mnt/wsl/resolv.conf）")
    p.add_argument("--nameserver", help="重建时写入的解析器（默认 10.255.255.254，或记录里的兜底）")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_repair)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        # 不带参数 = 直接看中文总览（而不是 argparse 的 usage 报错）
        print(helpdoc.render(None))
        return EXIT_OK
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg, path = load(args.config)
    if getattr(args, "state_dir", None):
        cfg["state_dir"] = args.state_dir
    cfg.source_path = str(path) if path else ""
    try:
        return int(args.func(cfg, args))
    except (EngineError, DohError, resolvconf.ResolvError) as exc:
        print(f"{PROGRAM}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print(f"\n{PROGRAM}: 中断", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())