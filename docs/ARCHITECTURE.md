# dnsbypass 架构（固定契约）

> **这份文档的目的是把架构钉死。** 改 bug / 加功能之前先读对应章节；
> 改完先跑 `python3 tests/architecture.py` —— 它把本文第 6 节的「不变量」逐条变成了
> 可执行断言。文档与断言不一致时，**以断言为准并更新本文**。

- 版本：0.1.0 ｜ 代码量：约 3900 行（11 个模块 + 启动器 + 3 个测试）
- 依赖：**只用 Python 标准库**（Python ≥ 3.11，需要 `tomllib`），没有任何 pip 包

---

## 1. 设计目标与非目标

### 目标

1. **把 Linux 侧的明文 DNS 换成经代理的 DoH**：`/etc/resolv.conf` 指向本机引擎，
   引擎只把查询交给 `https://dns.google/dns-query`（经已有的 HTTP 代理出口）。
2. **随时能逐字节回滚**：接管前记录原始形态与原始内容，`unbind` 后 `md5` 必须与接管前完全一致。
3. **引擎挂掉不能断网**：生成的 `resolv.conf` 里始终保留一个明文兜底 nameserver，
   引擎死了只退回"污染态"，不会变成"完全不能解析"。
4. **零依赖、可搬目录**：拷到任何目录都能跑，状态目录优先级 CLI > 配置文件 > 环境变量 > 默认。

### 非目标（**不要**往这些方向改**）

- ❌ 不做代理、不做翻墙、不改 Windows 设置、不接管路由、不做 TUN。
- ❌ 不缓存明文兜底拿到的应答（它可能是投毒的）。
- ❌ 不"智能猜测"用户想要什么：所有写系统的动作只信 `state/bind.json` 里的记录。

### 验收标准（全栈）

`audit` 的 `verdict` 为 `clean`/`light`、`probe` 无假 IP、`getent ahostsv4` 得到真实地址、
代理那一路（`curl -x $http_proxy …`）不受影响、`unbind` 后 `md5` 与基线一致。

---

## 2. 全景图

```
  用户
   │  ./dnsbypass  <子命令>
   ▼
┌──────────────────────────────────────────────────────────────┐
│ dnsbypass（启动器，14 行）                                     │
│   sys.path.insert(ROOT) → dnsbp.cli.main()                   │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ dnsbp/cli.py  (L5 编排层 —— 唯一被启动器调用的模块)             │
│   help config preflight audit probe run start stop status     │
│   bind unbind repair                                          │
└──┬────────┬──────────┬──────────┬───────────┬────────────────┘
   │        │          │          │           │
   │        │          │          │           └─▶ resolvconf.py (L2) 接管/回滚/修复
   │        │          │          └─────────────▶ preflight.py  (L4) 自检
   │        │          └────────────────────────▶ audit.py      (L3) 体检
   │        └───────────────────────────────────▶ engine.py     (L3) 解析引擎
   └────────────────────────────────────────────▶ doh.py / transport.py /
                                                  config.py / proxyenv.py / wire.py
```

运行期（`run`，通常由 `start` 以 root 拉起，绑特权端口后立刻降权）：

```
  glibc ──UDP/TCP :53──▶ Server ──▶ Resolver ──┬─▶ 缓存命中 → 直接回（重写 txid）
  (127.0.0.2)   │                              ├─▶ DoHClient ──HTTPS──▶ 代理 ──▶ dns.google
                │                              └─▶ 明文兜底（10.255.255.254 等，不缓存）
                └─ 每 5 秒把统计写进 state/engine.json
```

---

## 3. 分层与依赖规则（**不许出现反向边**）

| 层 | 模块 | 允许依赖 |
|---|---|---|
| **L0** 纯工具 | `wire.py`、`proxyenv.py`、`helpdoc.py`、`__init__.py` | 仅标准库 |
| **L1** 基座 | `config.py`、`transport.py` | L0 |
| **L2** 单一能力 | `doh.py`、`resolvconf.py` | L0–L1 |
| **L3** 组合能力 | `engine.py`、`audit.py` | L0–L2 |
| **L4** 自检 | `preflight.py` | L0–L3 |
| **L5** 编排 | `cli.py` | L0–L4（全部） |

规则：

1. 只允许 **L(n) → L(m)，m ≤ n**；实际方向永远是"上层 import 下层"。
2. **同层之间禁止互相 import**（`engine` ↔ `audit` 不许互引；共用逻辑下沉到 L0–L2）。
3. **不允许环**；除 `cli.py` 外，任何模块都不许 import `argparse`、不许 `print` 结果表格。
4. `resolvconf.py` 不许 import `engine.py`/`doh.py`（接管逻辑必须能在引擎起不来时单独工作）。

> `tests/architecture.py` 的第 1 项断言就是这张表：它解析所有模块的 AST，发现表外依赖或环即失败。

---

## 4. 模块契约

### 4.1 `dnsbp/wire.py` （L0，DNS 报文工具箱）
纯函数，无状态、无 IO。**所有报文解析/构造都必须在这里做**，别在 engine/resolvconf 里手写偏移量。

- 常量：`QTYPE_A=1`、`QTYPE_CNAME=5`、`QTYPE_AAAA=28`
- 读：`txid`、`rcode`、`is_response`、`header_counts`、`skip_name`、`decode_name`、
  `qname_text`、`question_key`、`min_ttl`、`parse_records`、`answers_of`
- 写：`build_query(name, qtype=QTYPE_A, qid=None)`、`with_txid(pkt, new_id)`
- 判定：`is_public_ip(text)`、`is_fake_ip(text)`（与 DSH `web_fetch` 的口径一致：
  `198.18.0.0/15`、`fd00::/8` 视为假 IP）

### 4.2 `dnsbp/proxyenv.py` （L0，代理环境变量）
- `CANONICAL_KEYS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")`
- `ProxyEnv`（dataclass：`http`、`https`、`all`、`no_proxy`、`source`、`raw`），
  `for_scheme()`、`has_any()`、`proxy_map()`、`no_proxy_entries()`
- `snapshot(environ=None)` 读环境；`recover_from_processes(uid=None, self_pid=None)` 扫
  `/proc/*/environ` —— **sudo 的 env_reset 会清掉代理，这是唯一的自救手段**
- `effective_proxy(env, override="")`、`mask(url)`、`describe(env)`、`no_proxy_covers(env, host)`

### 4.3 `dnsbp/config.py` （L1，配置）
- `DEFAULTS`（见第 9 节）｜`class Config(dict)` 支持属性访问与 `to_toml()`
- ⚠ **`Config()` 是空字典**：默认值只在 `load()` 里合并进来。自己 new 一个 Config 用
  （测试/嵌入调用）时必须写 `Config(DEFAULTS)`，否则 `cfg["bind_host"]` 会 KeyError。
- 优先级：**CLI 参数 > 配置文件 > 环境变量（仅 `state_dir`）> `DEFAULTS`**；
  配置文件是纯覆盖层，不写某项就沿用默认，**不要**把默认值再抄一份进配置文件。
- `candidate_paths()`：`<PROJECT_DIR>/config.toml` → `~/.config/dnsbypass/config.toml`
- `load(explicit=None) -> (Config, Path|None)`：浅合并覆盖层，**配置文件是纯覆盖层**
- `state_dir(cfg) -> Path`：优先级 **CLI `--state-dir` > `config.toml:state_dir` >
  `DNSBYPASS_STATE_DIR` > `<PROJECT_DIR>/state`**；相对路径一律锚定 `PROJECT_DIR`（**不是 cwd**）。
  ⚠ **有副作用：会 `mkdir -p` 建目录**（调用即落地，测试里记得清理）。
- `env_flag(name, default=False)`

### 4.4 `dnsbp/transport.py` （L1，明文 DNS 兜底）
`PlainDnsError`；`udp_query(server, pkt, timeout=3.0, port=53)`、`tcp_query(...)`、
`ask_a(server, name, timeout=3.0, port=53) -> list[str]`（校验 QR 位与 txid）。
**只用于兜底与体检，不用于主路径。**

### 4.5 `dnsbp/doh.py` （L2，DoH 客户端）
`DohError`；`DohResult(pkt, elapsed_ms, rcode, records)` 带 `answers()`/`describe()`；
`DohClient(url, timeout=8.0, proxy: ProxyEnv|None = None, force_proxy=True, user_agent=...)`：
- RFC 8484 二进制 POST（`application/dns-message`），**非 GET**（避免 URL/缓存问题）
- `_build_opener()` 用**显式 `ProxyHandler`、不挂 `no_proxy`** ⇒ DoH 这一跳永远走代理
- `query_raw(pkt)` / `query_name(name, qtype=QTYPE_A)`

### 4.6 `dnsbp/engine.py` （L3，引擎）
`EngineError`；`COUNTERS = ("served","hit","miss","doh_ok","doh_fail","fallback_ok","fallback_fail","malformed")`。

`Resolver(client, fallback_servers=None, ttl_cap=300, default_ttl=30, cache_max=4096,
doh_retries=1, retry_backoff=0.25, stats=None, log=print)`：
- `resolve(pkt) -> (bytes|None, source)`，`source ∈ {cache, doh, fallback:<server>, malformed, not-a-query}`
- 优先级：缓存 → DoH（含 1 次重试）→ 逐个明文兜底
- 缓存条件**只有一条**：`if key and source == "doh" and wire.rcode(resp) == 0:`
- 出站应答一律 `wire.with_txid(resp, request_id)`

`Server(resolver, host="127.0.0.1", port=5353, state_path=None, state_interval=5.0,
max_workers=32, log=print)`：`open_sockets()`（**UDP+TCP 同端口**，`SO_REUSEADDR`）、
`sockets_bound()`、`serve_forever()`、`stop()`、`_udp_loop`/`_handle_udp`、
`_tcp_loop`/`_handle_tcp`（2 字节长度前缀、`conn.settimeout(10.0)`）、
`_state_loop`/`_write_state("running"/"stopped")`（`.tmp` → `os.replace` 原子写）；并发走
`ThreadPoolExecutor(max_workers=32)`。

模块级：`_unprivileged_floor()`、`drop_privileges(log)`（认 `SUDO_UID`/`SUDO_GID`）、
`process_alive(pid)`。

### 4.7 `dnsbp/resolvconf.py` （L2，接管/回滚/修复）—— 最危险、最容易改错的模块
常量：`RESOLV_CONF`、`WSL_HOST_RELAY="10.255.255.254"`、`BIND_RECORD="bind.json"`、
`BACKUP_NAME="resolv.conf.backup"`、`TARGET_BACKUP_NAME="resolv.conf.target.backup"`、
`MANAGED_MARK="# 本文件由 dnsbypass 接管生成"`、`WSL_DEFAULT_TEMPLATE`。

- `inspect(path) -> ResolvView`（原始形态、模式、属主、内容、md5）
- `render(cfg, host=None, fallbacks=None) -> str`：`MANAGED_MARK` + 生成时间 +
  `nameserver 127.0.0.2` + 兜底 `nameserver` + `options timeout:2 attempts:1`
- `bind(cfg, target=RESOLV_CONF, dry_run=False, log=print) -> dict`
- `unbind(cfg, dry_run=False, log=print, target=None) -> dict`
- `repair(cfg, target=RESOLV_CONF, real=None, nameserver=None, dry_run=False, log=print) -> dict`
- 辅助：`is_managed(text)`、`wsl_default_text()`、`content_md5()`、`record_path`、
  `load_record`、`save_record`、`prepare_state_dir`、`detect_fallbacks`、
  `_chown_to_caller`、`_tmp_sibling`、`_remove_stale_tmp`、`_write_tmp_and_move`、
  `_atomic_write`、`_replace_with_regular`

### 4.8 `dnsbp/audit.py` （L3，体检）
`AuditReport` 的属性即对外契约：`polluted_canary`、`polluted_control`、`polluted_core`、
`polluted_user`、`fake_total`；`verdict`（:117-126）：

| 条件 | verdict | exit_code |
|---|---|---|
| DoH 全部不可用 | `doh-unreachable` | `EXIT_PREFLIGHT`(30) |
| `fake_total ≥ 3` 或 `polluted_core ≥ 2` | `heavy` | `EXIT_HEAVY`(20) |
| `polluted_canary ≥ 1` | `polluted` | `EXIT_HEAVY`(20) |
| `polluted_user ≥ 1` | `light` | `EXIT_LIGHT`(10) |
| 其余 | `clean` | `EXIT_OK`(0) |

另有 `should_bind = verdict in {"heavy","polluted"}`、`to_dict()`、`summary()`、`render()`；
`audit(cfg, client, user_domains=None, log=print)`、`probe_doh`、`local_resolver`、`write_report`。

> ⚠ 退出码只作"提示污染程度"用，**不要**把 `exit_code == 0` 当作"没有可比性差异"的唯一判据：
> anycast/CDN 域名（典型 `x.com`）会因就近节点不同被记成 mismatch。判定要看
> `polluted_core`/`polluted_control`/`fake_total`（`tests/full-stack.sh` 就是这么做的）。

### 4.9 `dnsbp/preflight.py` （L4，自检）
`run(cfg, client, live_probe=True) -> PreflightReport`，各项检查：
`check_python`、`check_proxy`、`check_doh`、`check_resolv`、`check_ports`、`check_engine`、`check_tls`；
其中 `check_ports` 用 `loopback_delivery(host, port, timeout=2.0) -> (bool|None, str)`
做"自问自答"式投递测试 —— **这是发现"镜像模式下 127.0.0.1:53 被 Windows 占着"的唯一手段**。

### 4.10 `dnsbp/helpdoc.py` （L0，帮助文本）
`OVERVIEW`（长文说明）、`COMMANDS: dict[str, str]`（每个子命令的中文详解）、
`render(topic=None) -> str`。**新加子命令必须同时在这里加条目**（架构断言会查）。

### 4.11 `dnsbp/cli.py` （L5，编排）
`PROGRAM="dnsbypass"`；每个子命令一个 `cmd_*(cfg, args)`；`build_parser()` 里
12 个子命令全部 `parents=[common]`。`--state-dir` 在**两处**都注册：顶层 parser 上
（无特殊默认 ⇒ 未传时是 `None`）与 `common` 上（`default=argparse.SUPPRESS`，
**否则解析子命令时会把顶层已解析到的全局值覆盖成 `None`** —— 这个坑踩过）。
两种写法都要能用：`./dnsbypass --state-dir X status` 与 `./dnsbypass status --state-dir X`。

关键辅助：`ensure_proxy(cfg, args)`（丢失代理时自动从 `/proc/*/environ` 找回）、
`build_client`、`build_resolver`、`emit(args, payload, text)`（统一的 `--json` 双输出）、
`tail_file`。`cmd_start` 是 `subprocess` 拉起
`[sys.executable, "-u", "-m", "dnsbp.cli", "--state-dir", …, "run", …]`，父进程只负责等待与报错。

---

## 5. 三条关键路径

### 5.1 查询路径（热路径，`run`）
1. `Server` 收包（UDP 或 TCP）→ 交 `Resolver.resolve(pkt)`。
2. `question_key(pkt)` 为 `None` ⇒ `malformed`；不是查询 ⇒ `not-a-query`（都不回包）。
3. 缓存命中（且未过期）⇒ `source="cache"`，**跳过 DoH**。
4. 否则 `DohClient.query_raw()`，失败重试 1 次（`retry_backoff=0.25`）。
5. DoH 仍失败 ⇒ 依次试 `fallback_servers`（明文），`source="fallback:<server>"`。
6. 回包前 `with_txid`；只有 `source=="doh" and rcode==0` 才写缓存（TTL 用 `min_ttl` 截断）。
7. 统计每 5 秒落盘 `engine.json` —— 崩溃后靠它判断"最后一刻谁在服务"。

### 5.2 接管路径（`bind`）
1. `prepare_state_dir`：确认 state 目录可写、归调用者所有。
2. `inspect(target)`：读 `/etc/resolv.conf` 的真实形态、模式、属主、内容、md5。
3. 备份策略（**只信"非自产内容"**）：
   - 当前内容**不是** `MANAGED_MARK` 开头 ⇒ 这才是"原始态"：
     没有备份就写一份；已有备份但备份本身是自产 ⇒ 用真原始内容替换；已有正常备份 ⇒ 不动。
   - 当前内容是自产 ⇒ 沿用记录里的 `original_kind/original_link_target/mode/uid/gid`；
     找不到匹配记录 ⇒ **拒绝接管（退出码 40）并提示 `repair`**。
4. 另存链接目标 `/mnt/wsl/resolv.conf` → `state/resolv.conf.target.backup`（**只读+另存，不写它**）。
5. `_replace_with_regular(target, render(...))`：把 `/etc/resolv.conf` 换成真文件。
6. `save_record`：`version=2`、`status="bound"`、`created_at`（重复 bind 保留首次、追加 `rebound_at`）。

### 5.3 回滚 / 修复路径
- `unbind`：读记录 → 若原形态是 `symlink` 就重建符号链接（**不需要备份内容**，顺带治好坏备份）；
  若是 `file` 就用备份写回；备份内容是自产且原形态是 file ⇒ **拒绝**并指向 `repair`。
  写完把 `status` 改 `unbound`。
- `repair`：用于"记录/备份已损坏"的场景。优先用 `target_backup` 恢复链接目标，
  否则按 `WSL_DEFAULT_TEMPLATE` 重建；再把 `/etc/resolv.conf` 恢复成指向它的符号链接。
  **幂等**：重复跑不改变结果。

### 5.4 启动 / 停止 / 降权
`start` 以 root 拉起 `run`；`run` 绑 53 → `drop_privileges()` 降到 `SUDO_UID`/`SUDO_GID`
（若端口高于 `ip_unprivileged_port_start` 才能彻底放弃权限）→ 写 `engine.pid`。
`stop` 读 pid、`SIGTERM`、等待 `process_alive()` 变假，**普通用户也能停**（进程已降权）。

---

## 6. 不变量（**改代码时不许破坏**；`tests/architecture.py` 逐条断言）

| # | 不变量 | 为什么 |
|---|---|---|
| **INV-1** | **绝不写穿符号链接目标**：只有 `/etc/resolv.conf` 被替换成真文件；`/mnt/wsl/resolv.conf` 只读、只另存副本 | 曾把 `/mnt/wsl/resolv.conf` 写坏 ⇒ 原始备份被覆盖，无法逐字节回滚（真实事故） |
| **INV-2** | 备份**只写一次**，且只在"当前内容非自产"时写；已有备份不覆盖（唯一例外：备份本身是自产 ⇒ 用真原始内容替换它） | 托管中再 bind 会把自产内容当"原始备份" |
| **INV-3** | 重复 bind 必须**沿用首次记录的 `original_kind/original_link_target/mode/uid/gid`** | 否则回滚到错误形态 |
| **INV-4** | 当前是自产内容但找不到匹配记录 ⇒ **拒绝接管**（退出码 40）并指向 `repair` | 宁可不动，不可猜 |
| **INV-5** | 每个出站应答必须 `with_txid(request_id)` | 缓存复用应答时会带回旧 txid，glibc/dig 直接丢弃（表现为"超时"） |
| **INV-6** | 只缓存 `source=="doh"` 且 `rcode==0` 的应答 | 明文兜底可能拿回投毒答案 |
| **INV-7** | DoH 出站**永远走代理**（`force_proxy_for_doh=True`），DoH opener 不挂 `no_proxy` | 直连 DoH 会被 RST/污染 |
| **INV-8** | `Server` 必须**同端口同时绑 UDP 与 TCP**；TCP 用 2 字节长度前缀 | 只绑 UDP 会在回退 TCP 的解析器上超时 |
| **INV-9** | 绑特权端口后必须 `drop_privileges`（认 `SUDO_UID`/`SUDO_GID`） | root 进程长期驻留不可接受 |
| **INV-10** | 临时文件用**唯一名**（`_tmp_sibling`），顺手清理旧版固定名；写系统文件失败一律转成 `ResolvError` 并提示"需要 root" | 固定临时名 + `fs.protected_regular=2` 曾造成 EPERM/EACCES（真实事故） |
| **INV-11** | **零第三方依赖**（只用标准库） | 要在没有 pip 的环境里跑 |
| **INV-12** | 禁止写死路径：家目录、`/home/...`、项目绝对路径；`state_dir` 相对路径锚定 `PROJECT_DIR` | 换目录/换用户必须照常工作 |
| **INV-13** | 退出码只在 `dnsbp/__init__.py` 定义、必须唯一且语义固定 | 调用方（脚本）依赖它 |
| **INV-14** | 每个子命令必须在 `helpdoc.COMMANDS` 里有中文条目 | `help` 是主要文档入口 |
| **INV-15** | `resolvconf_options` 至少 `timeout:2 attempts:1` | `timeout:1` 会让 glibc 抢不上就落到第二个（可能被投毒的）nameserver |
| **INV-16** | 生成的 `resolv.conf` **必须含至少一个明文兜底 nameserver** | 引擎被杀时退回污染态，而不是断网（full-stack 第 5 段就在测这个） |
| **INV-17** | `resolvconf.py` 不得 import `engine`/`doh` | 引擎起不来时接管/回滚仍要能用 |

---

## 7. 状态文件与数据契约（`state/`，已 gitignore）

`state_dir` 解析见 4.3。所有 JSON 都**原子写**（`.tmp` → `os.replace`），并 `_chown_to_caller`。

| 文件 | 内容 | 关键字段 |
|---|---|---|
| `bind.json` | 接管记录（**回滚的唯一依据**） | 见下 |
| `engine.json` | 引擎心跳与统计 | `status`(`running`/`stopped`)、`pid`、`host`、`port`、`doh_url`、`fallback[]`、`started_at`、`updated_at`、`stats{served,hit,miss,doh_ok,doh_fail,fallback_ok,fallback_fail,malformed}`、`cache_entries` |
| `engine.log` | 引擎日志（`status` 会尾巴显示） | 文本 |
| `engine.pid` | 引擎 PID | 整数 |
| `audit.json` | 最近一次 `audit` 报告 | `verdict`、`exit_code`、`polluted_canary/control/core/user`、`fake_total`、各域名结果 |
| `resolv.conf.backup` | **原始** `/etc/resolv.conf` 内容（原形态是 file 时用于回滚） | 文本 |
| `resolv.conf.target.backup` | 符号链接目标（`/mnt/wsl/resolv.conf`）的原始内容 | 文本 |
| `forensics/` | 出事时的取证副本（人工放的） | 文本 |

`bind.json`（**version 2，字段是契约，只能增不能改语义**）：

```
version=2            created_at / created_at_text       target
original_kind        ("symlink" | "file" | "missing")
original_link_target original_mode original_uid original_gid
dnsbypass_nameserver fallback_nameservers[]             desired_content
status               ("planned" | "bound" | "unbound" | "repaired")
backup_path          target_backup_path
inherited_original   current_was_managed
rebound_at / rebound_at_text     （重复 bind 时追加，created_at 保留首次）
unbound_at                       （unbind 时）
repair_source                    （repair 时：用的是 target_backup 还是模板）
```

---

## 8. 退出码与来源标签

| 常量 | 值 | 含义 |
|---|---|---|
| `EXIT_OK` | 0 | 正常 / `audit` clean |
| `EXIT_LIGHT` | 10 | `audit` 有轻微污染 |
| `EXIT_HEAVY` | 20 | `audit` 明显污染（`heavy`/`polluted`） |
| `EXIT_PREFLIGHT` | 30 | 前置条件不满足 / DoH 不可用 |
| `EXIT_ERROR` | 40 | 其余错误（含"拒绝接管"`ResolvError`） |

`Resolver.resolve()` 的来源标签：`cache`、`doh`、`fallback:<server>`、`malformed`、`not-a-query`
（前三个会回包，后两个不回；`--json` 输出与 `engine.json` 统计都用这些标签）。

---

## 9. 配置项索引（`DEFAULTS`，纯覆盖层）

| 分组 | 键（默认值） |
|---|---|
| DoH / 网络 | `doh_url`(`https://dns.google/dns-query`)、`timeout`(8.0)、`doh_retries`(1)、`upstream_proxy`(空)、`force_proxy_for_doh`(True)、`require_proxy`(True) |
| 缓存 | `ttl_cap`(300)、`default_ttl`(30)、`cache_max_entries`(4096) |
| 监听 | `listen_host`(127.0.0.1)、`listen_port`(5353)、`bind_host`(**127.0.0.2**)、`bind_port`(53) |
| 接管 | `fallback_nameservers`(空 ⇒ 自动探测)、`resolvconf_options`(`timeout:2 attempts:1`)、`state_dir`(空) |
| 体检 | `canary_domains`(10)、`control_domains`(4)、`core_domains`(3)、`fake_ip_blacklist`(21 项)、`light_max`(2) |

> `bind_host` **必须**是 `127.0.0.2` 一类"第二个环回地址"，不能是 `127.0.0.1`：
> 镜像模式下 `127.0.0.1:53` 被 Windows 侧占着，绑定看似成功但收不到包（`Recv-Q` 恒为 0）。

---

## 10. 改动指南

### 加一个子命令（4 处，缺一不可）
1. `cli.py`：写 `cmd_xxx(cfg, args)`；
2. `cli.py:build_parser()`：`add_parser("xxx", parents=[common], help=…)`；
3. `helpdoc.py`：`COMMANDS["xxx"] = "…中文详解…"`；
4. `tests/architecture.py` 会自动检查第 3 步（不用改测试）。

### 加一条审计域名
改 `config.py:DEFAULTS` 的 `canary_domains`/`core_domains`/`control_domains`
（或用户配置覆盖）。**别**在 `audit.py` 里写死域名。

### 换 DoH 上游 / 加兜底
只用改配置（`doh_url`、`upstream_proxy`、`fallback_nameservers`）。
**注意**：国内 DoH（如 `dns.alidns.com`）对被墙域名同样返回投毒答案，所以"换国内 DoH"
不是修法，除非做成按域名分流（未实施，见第 12 节）。

### 改接管内容 / 接管方式（高危）
必须同时处理：`MANAGED_MARK`（`is_managed` 依赖它）、`WSL_DEFAULT_TEMPLATE`、
`render()`、`bind/unbind/repair`、INV-1/2/3/4/10、`tests/resolvconf-sandbox.sh` 的用例。
**动手前先读第 5.2/5.3 节和 README 的「出过的坑」。**

### 修 bug 的流程
1. 在 `tests/resolvconf-sandbox.sh`（沙箱、免 root）或 `tests/architecture.py` 里**先加一条会失败的断言**；
2. 改代码；
3. `python3 tests/architecture.py` + `tests/resolvconf-sandbox.sh` 全绿；
4. 涉及真机的改动再跑 `sudo tests/full-stack.sh`（它自带回滚）；
5. 更新本文/README 里对应的说法。

### 明确不许做的事
写死路径；加 pip 依赖；在 `engine.py` 里做接管；把明文兜底答案写进缓存；
绕过 `with_txid`；用固定名临时文件；在 `cli.py` 以外 import `argparse`；
让 `audit` 的退出码变成"唯一判据"；改 `bind_host` 为 `127.0.0.1`。

---

## 11. 测试与验收

| 命令 | 需要 root | 覆盖 |
|---|---|---|
| `python3 tests/architecture.py` | 否 | 分层/依赖方向、INV 断言、退出码、help 覆盖、零依赖、无写死路径 |
| `tests/resolvconf-sandbox.sh` | 否 | 28 项：首次 bind / 托管中重复 bind / unbind / 伪造坏记录被拒(40) / repair / repair 幂等 / 旧固定名 tmp 不挡写入（全在 `mktemp` 沙箱，不碰系统文件） |
| `sudo tests/full-stack.sh` | 是 | 真机 8 段：起点 md5 → 起引擎(53) → bind（不写穿目标）→ 端到端解析 + audit 判定 → 代理那一路 204 → `kill -9` 保命线 → 重复 bind 三项不变 → unbind+stop 逐字节还原（`trap` 保证收尾一定回滚） |

验收基线：`/etc/resolv.conf` → `/mnt/wsl/resolv.conf` 的符号链接，两文件
`md5 = ccd28ae0776549eb3926db2148a50bff`（200 字节）；`/mnt/wsl` 只有 `resolv.conf`。

---

## 12. 已知技术债与未实施项

1. **国内域名变慢（已记录，未修）**：DoH 经代理出口解析 ⇒ 国内域名拿到"海外视角"的 CDN 节点
   （实测 taobao `155.102.209.237` 10.0s vs 本地 `124.239.228.64` 0.05s）。
   方向：按域名分流（国内域名走国内 DoH 或明文，复用 `fake_ip_blacklist`/`is_fake_ip()` 判定）。
   **用户决定先不动**（2026-10-03）。
2. **不会自动接管**：没有 systemd unit / WSL 启动钩子，重启 WSL 后需手动
   `start` + `bind`（曾考虑 `dnsbypass install`，未实施）。
3. **明文兜底不加密**：兜底那一跳仍是明文 53，其答案永不缓存。
4. **`audit` 会误报 anycast/CDN**（典型 `x.com`）：判定要看 core/control/fake_total。
5. **Windows 侧 DoH 路线未走**：用户选择"不动 DNS"。
6. `state/` 里由 root 跑出来的文件（`audit.json`/`bind.json`）属主是 root，
   普通用户 `status` 只能读；已靠 `_chown_to_caller` 尽量收敛，但历史文件可能残留。