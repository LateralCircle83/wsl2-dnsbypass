# dnsbypass

把自己变成 WSL 里的**本地 DoH 解析器**，然后接管 `/etc/resolv.conf` —— 目的只有一个：
让本机的**明文 DNS** 不再拿到被投毒的假地址。

> 它**不**负责让 agent 访问被墙的站点。`web_fetch`/`curl` 走 HTTP 代理时，`CONNECT` 里是域名，
> 由出口节点解析，本地 DNS 从来不参与。本工具修的是"直连诊断"那一路：
> `getent hosts`、`git ls-remote`、`nslookup`、以及任何不认代理却要解析域名的程序。

## 解决的痛点

> **WSL2 镜像模式（`networkingMode=mirror`）+ 非 TUN 模式的代理客户端（nano）=
> 明文 DNS 全程暴露，被投毒也没人管。**

链路是这样的：

1. **镜像模式**下 Linux 与 Windows 共享网络栈与环回，WSL 的 `autoProxy` 只做一件事：
   把 Windows 的系统代理注入成环境变量（`http_proxy` / `https_proxy` / `HTTP_PROXY` /
   `HTTPS_PROXY` = `http://127.0.0.1:65532`，外加 `NODE_USE_ENV_PROXY=1` 与 `NO_PROXY`）。
2. **代理客户端没开 TUN**（本机用 nano，只暴露一个 HTTP 代理端口）。不开 TUN 时它**不管 DNS**：
   域名解析照样走 `/etc/resolv.conf` → `10.255.255.254`（WSL 宿主中继）→ Windows 宿主解析器
   （国内递归、**明文 53**）。
3. **明文 53 一出海就被投毒**：本机实测 canary 域名 9/10 中招，`www.google.com` → `157.240.7.20`、
   `www.youtube.com` → `31.13.92.37`、`www.reddit.com` → `174.132.167.252`，全是不可路由的假地址。
4. **代理开着也没用**：HTTP 代理不参与 DNS。走代理的程序在 `CONNECT host:443` 里带的是**域名**，
   由出口节点解析，本地的假地址与它无关；而**不走代理**的程序（`getent`、`git`、`apt`、
   各种不读代理的 SDK/工具）拿到的就是假地址 —— 于是出现"浏览器/agent 能上谷歌，但 `git`
   却要 135 秒超时"这种自相矛盾的现象。
5. **"把自己设成系统代理"也解决不了**：glibc 读的是 `/etc/resolv.conf`，它不认 `http_proxy`。
   在代理链上再套一层本地代理，DNS 仍然走原路。**要修就必须让 glibc 换掉解析器**——
   这正是本工具做的事。
6. **为什么不干脆开 TUN**：TUN 会全面接管路由，所有流量（包括本来直连更快的国内流量）都进隧道。
   本环境明确选择"非 TUN + 按需代理"，所以这里走**第三条路**。

因此本工具的定位是：**不改代理设置、不动 Windows、不开 TUN，只在 Linux 侧把明文 DNS 换成
经代理的加密 DNS（DoH），并且随时能逐字节回滚。**

三条路的对比：

| 方案 | 代价 | 本工具 |
|---|---|---|
| 开 TUN | 全流量进隧道，国内流量绕远 | ✗ |
| Windows 侧开 DoH | 只改 Windows 解析器；WSL 若走 tunneling 才跟着变，不确定 | ✗（曾试，用户选择不动 DNS）|
| **Linux 侧接管 resolv.conf + DoH** | 需要 root 占 53；国内域名会拿到"海外视角"的 CDN 节点（见「已知限制」）| ✓ |

## 目录

- [解决的痛点](#解决的痛点) —— 为什么会有这个工具
- [原理](#原理) / [为什么必须"进系统"](#为什么必须进系统)
- [用法](#用法) / [帮助](#帮助) / [换个目录也能跑](#换个目录也能跑)
- [项目架构](docs/ARCHITECTURE.md) —— 模块契约与**不可破坏的不变量**（改 bug 前先看这个）
- [测试](#测试) / [已知限制](#已知限制)
- [救命命令：`repair`](#救命命令repair) / [安全](#安全) —— 接管失败怎么恢复

## 为什么必须"进系统"

`/etc/resolv.conf` 不支持给解析器指定端口，所以想被 glibc 采用只能占 **53**；
而端口 53 低于 `net.ipv4.ip_unprivileged_port_start`（本机 1024），普通用户绑不上 ⇒
`bind`/`unbind` 与 `run --port 53` 需要 sudo。这是协议与内核限制，不是实现偷懒。

WSL 下 `/etc/resolv.conf` 一般是指向 `/mnt/wsl/resolv.conf` 的符号链接（root 所有、目录 sticky），
所以接管 = **把符号链接换成真文件**，并留下记录；`unbind` 按记录原样恢复（含符号链接本身）。

### 为什么是 127.0.0.2 而不是 127.0.0.1:53

WSL **镜像网络模式下环回是与 Windows 共享的**，Windows 侧持有 `127.0.0.1:53`
（DNS 代理/隧道）。Linux 侧绑 `127.0.0.1:53` 会**成功**，但发给它的包被吞掉——
`ss` 显示监听正常、`Recv-Q` 永远是 0、`served=0`，甚至连 `sendto` 都会卡住。
`127.0.0.2` / `127.0.0.55` 这类别的环回地址没有这个问题（实测可用），
所以 `bind_host` 默认 `127.0.0.2`；`preflight` 里有一项 `接管环回` 就是专门发包给自己验这个坑的
（绑定成功 ≠ 收得到）。NAT 模式下不存在该问题，`127.0.0.1` 也能用。

## 原理

```
应用 → glibc → 127.0.0.2:53 (UDP/TCP)   ← 为什么不是 127.0.0.1，见下
                 └─ 转发引擎 ── 命中缓存？→ 修正事务 ID 后回包
                              └─ 未命中 → HTTPS POST 原始报文（RFC8484 线格式）
                                           经 http_proxy 的 CONNECT 隧道 → DoH 端点
                                           → 原样透传响应（只读 TTL / 只认 RCODE=0 才缓存）
                              └─ DoH 失败 → 明文兜底解析器（保命优先于正确）
```

* **零解码透传**：不解析、不重构请求报文，EDNS0 / DNSSEC / 未知 RR 都能过。
* **事务 ID 修正**：回包 ID 一律改成请求方的 ID。缓存里存的是"第一次"的 ID，
  不修正的话 glibc 会丢弃回包并超时——表现为"越命中越查不出来"（本项目第一版就踩了这个坑）。
* **只缓存成功应答**：`RCODE != 0` 一律不缓存。
* **只缓存 DoH 的应答**：明文兜底的答案可能已被投毒，缓存它等于把污染钉住 5 分钟，
  所以兜底应答只回给当前这一次查询。`doh_retries`（默认 1）让偶发的 TLS 握手超时
  先短退避重试一次，再降级。
* **引擎自带兜底**：`fallback_nameservers` 没配时自动取"当前 resolv.conf 里除自己以外"的解析器
  （探不到就退回 WSL 的 `10.255.255.254`），启动日志里会打印生效清单。
* **`options timeout:2 attempts:1`**：冷启动第一次 DoH 查询要 0.3–1.3s，原来写 `timeout:1`
  会让 glibc 等不及就翻到第二个（明文、被投毒的）nameserver —— 表现为"刚起好就解析出假地址"。

## 实测：被投毒的站点现在怎么样

接管之后（引擎 `127.0.0.2:53`，`/etc/resolv.conf` 已指向它）分别测了两条路：

| 目标 | 走代理（`web_fetch` 那一跳，CONNECT 带域名） | 直连（`--noproxy '*'`，用我们的干净 DNS） |
| --- | --- | --- |
| google / youtube / wikipedia / reddit / instagram / bbc / x.com | 200 | 000（8s 超时，IP 层封锁） |
| dropbox / nytimes | 200 | 000 |
| signal.org | 301 | 000（0.6s 被拒） |
| **github.com** | 200 | **200（`20.27.177.113`，约 10s）** |

两条结论：

1. **`web_fetch` 本来就不受本地 DNS 污染影响**——它走 `http_proxy`，`proxyRouteFor()` 判定
   "走代理"后既不做本地解析、也不做公网地址校验（"the proxy performs the lookup"），
   所以 google / x.com 这类域名一直能取到。这也说明：**别把"能上 google"当成 dnsbypass 的功劳**。
2. **dnsbypass 的价值在直连那一路**：github 以前 `git ls-remote` 要 135s 超时
   （默认查询只拿到不可路由的假 IPv6），现在直连 3/3 返回 200。而 google / reddit 这些
   即使拿到了真地址（`142.251.x` / `151.101.x`），直连依然连不上——**假地址与 IP 层封锁是两码事**，
   本工具只解决前者。

## 帮助

```bash
./dnsbypass help            # 中文总览：做什么/不做什么、为何要 sudo、典型流程、退出码、排障
./dnsbypass help bind       # 单个命令：用途、参数、副作用、例子
./dnsbypass                  # 不带参数 = 同一份总览（不是 argparse 报错）
```

## 换个目录也能跑

项目里**没有写死路径**：所有相对路径都以**代码所在目录**为基准，而不是当前工作目录。

```bash
cp -r dnsbypass /opt/dnsbypass
cd / && /opt/dnsbypass/dnsbypass status      # 一样能用，状态在 /opt/dnsbypass/state/
```

想把状态挪到别处（项目目录只读、或者想跑两份互不干扰的实例）：

```bash
dnsbypass --state-dir /var/lib/dnsbypass start --port 53
DNSBYPASS_STATE_DIR=/var/lib/dnsbypass dnsbypass status
```

优先级：`--state-dir` > `config.toml:state_dir` > `DNSBYPASS_STATE_DIR` > `<代码目录>/state`。
`start` 会把解析好的状态目录**绝对路径**显式传给后台引擎，所以父子进程的 cwd 不同也不会各写一份。

## 用法

```bash
cd ~/project-1/dnsbypass
./dnsbypass --help

./dnsbypass config                      # 看生效配置与来源
./dnsbypass preflight                   # 启动前体检：代理、DoH、端口、resolv.conf
./dnsbypass audit                       # 污染审计（只读，写 state/audit.json）
./dnsbypass probe --domains www.google.com,github.com
./dnsbypass start                       # 后台起引擎（默认 127.0.0.1:5353）
./dnsbypass status
sudo ./dnsbypass bind                   # 接管 /etc/resolv.conf（先备份、后记录）
./dnsbypass help                        # 忘了怎么用就看这个
./dnsbypass probe --domains www.google.com   # 接管后应该拿到真值
sudo ./dnsbypass unbind                 # 按记录回滚
sudo ./dnsbypass repair                 # 备份坏了 / 记录丢了时的救命命令（恢复 WSL 原始态）
./dnsbypass stop
```

需要让 `127.0.0.1:53` 生效时，引擎也要在 53 上跑（`resolv.conf` 不能指定端口）：

```bash
sudo ./dnsbypass start --port 53        # 绑定后自动降权回 SUDO_UID
sudo ./dnsbypass bind
sudo ./dnsbypass unbind && ./dnsbypass stop
```

### sudo 会吃掉代理（已自动处理）

`sudo` 默认 `env_reset` 且 `-E` 在 sudo 1.9 上被忽略（`sudo: preserving the entire
environment is not supported, '-E' is ignored`），所以提权后的进程**看不到**
`http_proxy`/`https_proxy`，DoH 那一跳直接断。三种解法，按优先级：

1. **自动找回（默认行为）**：检测到 `SUDO_UID` 且环境里没有代理时，扫 `/proc/*/environ`
   从**调用者身份**的其它进程（shell / dsh）里把代理捡回来，日志会写明来源，例如
   `代理：sudo 的 env_reset 丢掉了它，已从 /proc/1234/environ(uid 1000) 找回 http://127.0.0.1:65532`。
2. **写进配置**（推荐，最可预测）：`config.toml` 里 `upstream_proxy = "http://127.0.0.1:65532"`。
3. **命令行**：`sudo ./dnsbypass start --port 53 --proxy http://127.0.0.1:65532`
   （`--proxy` 只影响 DoH 出站，不会改系统里的代理设置）。

`dnsbypass` 不改任何代理配置：它只**出站**到 DoH 端点，方向与 `web_fetch` 走代理相反，
所以两者不会打架（详见 `## 为什么必须"进系统"`）。

### 出过的坑：旧版会把 resolv.conf 写穿、还拿自产内容当备份（0.1.0 已修）

`/etc/resolv.conf` 在 WSL 里是指向 `/mnt/wsl/resolv.conf` 的**符号链接**。旧实现有两个
要命的错误，实测把用户环境"永久替换"过：

1. `bind` 生成新内容后**顺着符号链接写进了 `/mnt/wsl/resolv.conf`**，把 WSL 的原始
   内容覆盖掉；而备份只存了 `/etc/resolv.conf` 那一层。
2. `bind` 无条件用"当前内容"覆盖 `state/resolv.conf.backup`。于是**托管期间再 bind 一次**，
   备份就变成程序自己生成的内容，记录里的原形态也从 `symlink` 变成了 `file`——原始信息丢失。
   之后 `unbind` 只会把这份自产内容写回去、且再也不会重建符号链接，看起来就是"被换了"。

现在的保证（都有沙箱用例）：

* **绝不写穿链接目标**：`/mnt/wsl/resolv.conf` 保持原样，只在
  `state/resolv.conf.target.backup` 另存一份双保险。
  ⇒ **接管期间这两个文件内容不一样是正常的、也是必须的**：`/etc/resolv.conf` 是我们
  生成的真文件（指向 `127.0.0.2`），`/mnt/wsl/resolv.conf` 是 WSL 原文。glibc 只看前者；
  正因为后者没被动过，随时能逐字节回滚。
* **备份只写一次，且只写"不是程序自己生成"的内容**；重复 `bind` 不会覆盖它。
  若发现备份是旧版的坏内容（自产），`bind`/`unbind` 会顺手用真实原文治好它。
* 托管中重复 `bind` 会**沿用首次记录的原始形态**（原本是符号链接就永远记得是符号链接）。
* `unbind` 发现备份是自产内容时：原形态是**普通文件**才拒绝执行（退出码 40）并指向 `repair`；
  原形态是**符号链接**且链接目标健康时照常回滚（用不到那份备份内容），并顺手治好备份。
* 临时文件用 `<名字>.dnsbypass.<pid>.<随机>.<tag>` 唯一命名，并会清理旧版固定名残留。
  这是踩过的坑：旧版固定叫 `resolv.conf.dnsbypass.tmp`，一次以普通用户身份失败留下的文件，
  会让之后**连 root 都写不进去**——Ubuntu 默认 `fs.protected_regular=2` 专门防这种
  "临时文件抢注"，且不豁免 root（实测 `sudo repair` 直接 PermissionError）。

## 救命命令：`repair`

不管中间发生了什么（备份是坏的、记录丢了、状态目录被换过），只要想让系统回到
"没被碰过"的样子：

```bash
sudo ./dnsbypass repair --dry-run      # 先看它打算写什么、来源是什么
sudo ./dnsbypass repair                # 重建 WSL 原始态并恢复符号链接
sudo ./dnsbypass repair --nameserver 10.255.255.254
```

它把 `/mnt/wsl/resolv.conf` 写成 WSL 默认模板（就是 `generateResolvConf = true` 时
WSL 自己生成的原文，本机 200 字节、md5 `ccd28ae0776549eb3926db2148a50bff`），再把
`/etc/resolv.conf` 变回指向它的符号链接。**幂等**，可以反复跑；逐字节等于 WSL 原文。
不想用脚本时，Windows 里 `wsl --shutdown` 也能让 WSL 重建这两者。

### 退出码（便于脚本判断）

| 码 | 含义 |
|----|------|
| 0  | 干净 / 正常 |
| 10 | 轻微污染（仅对照组或少量异常） |
| 20 | 污染 / 重污染（canary 命中或多处假 IP）|
| 30 | 前置条件不满足（DoH 不通）|
| 40 | 运行错误 |

## 安全

* 默认**不写任何系统文件**：`config` / `preflight` / `audit` / `probe` / `status` 全是只读。
* 只有 `bind` 会改 `/etc/resolv.conf`，且：先把**非自产**的原始内容备份到
  `state/resolv.conf.backup`（只写一次，重复 bind 不覆盖），再写 `state/bind.json`
  （记录原形态、属主、权限、链接目标），失败会明确报"需要 root"。
  **不会写穿符号链接目标** `/mnt/wsl/resolv.conf`（另存 `state/resolv.conf.target.backup`）。
* `unbind` 只信记录、不猜测；记录不存在时拒绝执行；备份是自产内容时也拒绝执行并指向 `repair`。
* `repair` 是唯一"重建"而非"还原"的命令：内容取原始备份，拿不到就按 WSL 默认模板重建，
  并恢复 `/etc/resolv.conf` 的符号链接形态；幂等、可 `--dry-run` 预览。
* 引擎**只出站**到配置的 DoH 端点；`fallback_nameservers` 是唯一会发明文的地方，默认自动取原 resolv.conf 的解析器。
* root 绑定端口后立即 `setgroups/setgid/setuid` 降权到调用者。

## 测试

接管逻辑的回归测试**不需要 root、不碰系统文件**（全在 `mktemp` 沙箱里跑）：

```bash
python3 tests/architecture.py   # 架构守护：依赖方向、退出码、帮助覆盖、不变量（无需 root）
tests/resolvconf-sandbox.sh     # 28 项检查：bind / 重复 bind / unbind / 坏记录被拒 / repair / 幂等（无需 root）
sudo tests/full-stack.sh        # 真机全栈终测：起引擎(53) → bind → 端到端解析 → 代理那一路
                                #   → kill -9 保命线 → 重复 bind 安全性 → unbind+stop → 逐字节回滚校验
                                #   （trap 保证无论如何都回滚）
```

`tests/architecture.py` 是"固定架构"的那把锁：它把 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
里的不变量变成可执行断言（模块分层不许反向依赖、退出码必须唯一且与 `__init__.py` 一致、
每个子命令必须在 `helpdoc.COMMANDS` 里有中文帮助、缓存只缓存 DoH 应答、Server 必须同时绑
UDP+TCP、源码里不许出现写死的家目录路径……）。**改代码后先跑它**，比读文档快。

## 已知限制

* 只做 **A 记录**的审计与对比；引擎本身透传任意类型。
* DoH 端点选择依赖网络现实：本机可直连的海外 DoH 只有 ControlD / NextDNS / HiNet / Yandex；
  `dns.google` 必须走代理。**国内** DoH（`dns.alidns.com` / `doh.pub`）直连可用，但对被墙域名
  返回的是同样的投毒答案（实测 `www.google.com` → `157.240.7.20`、`174.132.167.252`），
  不能当唯一上游；它只适合在"国内外分流"方案里承担国内那一半。
* ⚠ **国内域名会变慢（已知限制，尚未修）**：所有查询都经代理跳去 `dns.google`，回来的国内 CDN
  节点是"海外视角"的节点。同一台机器、同一域名、只换 IP 的对照实验：

  | 域名 | DoH 答案（现用） | WSL 本地答案 |
  |---|---|---|
  | www.taobao.com | `155.102.209.237` → 10.001s | `124.239.228.64` → 0.053s |
  | www.qq.com | `43.159.109.55` → 3.839s | `42.81.179.153` → 0.090s |
  | www.baidu.com | `98.98.225.192` → 1.012s | `124.237.178.35` → 0.063s |
  | mirrors.aliyun.com | `36.104.156.5` → 3.52s | `36.104.156.1` → 0.10s |
  | registry.npmmirror.com | `163.181.39.184` → 1.36s | `150.139.241.35` → 0.08s |

  **修法（未实施，用户选择先记录）**：给国内后缀域名加一条"明文优先"路径——先问本地解析器
  （国内域名本来就没被污染、且就近），答案命中假 IP 黑名单或非公网地址时再回退经代理的 DoH；
  国外域名逻辑不变。不需要新依赖，也不会引入"引擎解析自己"的自环；分流只需复用
  `config.py` 里已有的 `fake_ip_blacklist` 与 `is_fake_ip()`。
* 无代理时 DoH 域名自身可能被投毒（自举问题）：`dns.hinet.net` 实测解析到 `199.59.148.96`。
  这种情况下需要先在 `/etc/hosts` 钉住端点 IP；`preflight` 会检查并提示。
* `fallback_nameservers` 是明文请求，必然可能被投毒——它只是"DoH 挂了别断网"的保命线；
  配置留空时会**自动沿用原 resolv.conf 里的解析器**写进去（排除 127.0.0.1），回滚时原文件原样恢复。
* 接管时不保留原文件的 `search` / `domain` 行（当前 WSL 里是空的）；需要的话在 `resolvconf_options`
  之外手动补，或在 `render()` 里扩展。
* 未接管时不要指望它影响任何东西：它只是一个监听着的转发器。
* `audit` 对 **anycast/CDN** 域名可能误报"污染"：例如 `x.com` 的 DoH 真值
  `162.159.140.229` 与本地 `172.66.0.227` 同为 Cloudflare 不同节点，属正常差异。
  对照组（control）只看"是否命中假 IP 黑名单"，canary 的 mismatch 只是提示，判定看整体分级。