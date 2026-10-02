"""中文帮助文档（`dnsbypass help` / `dnsbypass help <命令>`）。

文档集中放在这里，理由：cli.py 只负责"怎么执行"，这里只负责"怎么说清楚"。
改文案不用碰逻辑，也方便以后加 `help topics`。
"""
from __future__ import annotations

OVERVIEW = """\
dnsbypass —— 本机 DoH 接管工具（v0.1）
═══════════════════════════════════════════════════════════════════════════

【一句话】
把被投毒的明文 DNS 换掉：本机自己起一个 DoH 转发器，然后接管 /etc/resolv.conf。

【它做什么】
  明文 DNS（UDP/TCP 53）在国内会被抢答，返回 31.13.92.37 / 104.244.42.197 /
  157.240.7.20 之类的假地址。dnsbypass 让本机的 DNS 走加密的 DoH（RFC8484 线格式），
  再把干净答案回给发起查询的程序。

【它不做什么】（重要，别误会）
  * 它不翻墙。走 HTTP 代理的程序（web_fetch / curl -x / git 配了 proxy）在 CONNECT 里
    发的是**域名**，由代理出口自己解析，本地 DNS 从不参与 —— 那一路本来就没事。
    本工具修的是"直连那一路"：getent / nslookup / 不认代理却要解析域名的程序 / 直连诊断。
  * 它不改 Windows 侧的 DNS，也不管代理端的安全 DNS。
  * 它不处理 DoH 端点本身被墙的问题 —— 那一跳靠 http_proxy 出去。所以默认要求有代理。

【为什么必须"进系统"（为什么要 sudo）】
  glibc 只认 /etc/resolv.conf，而它**不支持给解析器指定端口**：
  想让系统用上我们，就只能占 53 端口。端口 53 低于
  net.ipv4.ip_unprivileged_port_start（本机 1024），普通用户绑不上 ⇒ bind/unbind
  和 `run --port 53` 需要 root。这是内核与协议的限制，不是实现偷懒。
  不想用 sudo 也能试：`run --port 5353`（前台跑，然后用 `dig @127.0.0.1 -p 5353` 验证）。

【为什么接管地址是 127.0.0.2 而不是 127.0.0.1:53】
  WSL 镜像网络模式下**环回是与 Windows 共享的**，Windows 侧持有 127.0.0.1:53
  （DNS 代理/隧道）。Linux 侧绑 127.0.0.1:53 会"成功"，但发给它的包被吞掉：
  ss 显示监听正常、Recv-Q 恒为 0、统计 served=0，甚至 sendto 会卡住。
  换个环回地址（127.0.0.2 / 127.0.0.55）就正常 —— 这也是 preflight 里
  "接管环回"那一项要发包给自己的原因：绑定成功 ≠ 收得到。
  NAT 模式下没有这个问题，bind_host 用 127.0.0.1 也行。

【典型流程】
  # 0) 先看看现在有多脏（只读，不改任何东西）
  ./dnsbypass audit

  # 1) 体检：代理通不通、DoH 通不通、53 能不能占、环回收不收得到包
  ./dnsbypass preflight

  # 2) 起引擎（占 53，需要 root；sudo 会清掉代理变量，程序会自动找回）
  sudo ./dnsbypass start --port 53

  # 3) 接管（自动备份 + 记录，可回滚）
  sudo ./dnsbypass bind

  # 4) 验证
  getent ahostsv4 www.google.com      # 应该是 142.251.x 而不是 104.244.42.197

  # 5) 回滚（想撤销时）
  sudo ./dnsbypass unbind && ./dnsbypass stop

【命令总览】
  config      显示最终生效的配置、来源文件、状态目录、代理快照
  preflight   启动前体检（只读）；退出码 30 = 有致命项没过
  audit       污染审计：DoH 真值 vs 本机明文，分级给退出码（适合脚本/定时）
  probe       单个域名的 DoH 真值 vs 明文对比（排查用）
  run         前台起转发引擎（调试用；--port 5353 免 sudo）
  start       后台起转发引擎（真正常用；配 --port 53）
  stop        停后台引擎（引擎会降权到调用者 uid，所以不用 sudo）
  status      看引擎活着没、resolv.conf 指向谁、统计与缓存
  bind        接管 /etc/resolv.conf（需 root；先备份后记录）
  unbind      按记录回滚（符号链接、权限、内容原样恢复）
  repair      把 resolv.conf 恢复成 WSL 原始态（记录/备份坏掉时的救命命令）
  help        你正在看的这个；`help <命令>` 看单个命令的细节

【退出码】
  0  = 干净 / 成功
  10 = 轻度污染（不一致域名 ≤ light_max，默认 2）
  20 = 重度污染（含 core 域名，或假 IP 命中）
  30 = 前置检查未通过（preflight）
  40 = 出错（参数、网络、权限、文件）

【文件都放哪】
  代码      项目目录（可整体搬到任意路径，见下）
  配置      <项目目录>/config.toml  或  ~/.config/dnsbypass/config.toml（后者优先级低）
  状态      <项目目录>/state/ ：engine.json（引擎状态）、engine.log（引擎日志）、
            audit.json（最近审计报告）、bind.json（接管记录）、resolv.conf.backup（原文件）
            以及 resolv.conf.target.backup（符号链接目标的那份原始内容，用于双保险）
  改位置    环境变量 DNSBYPASS_STATE_DIR=...  或全局参数 --state-dir <目录>

【能换个目录跑吗】
  能。项目里没有写死路径：所有相对路径都以**代码所在目录**为基准，而不是当前工作目录。
  cp -r dnsbypass /opt/dnsbypass && cd / && /opt/dnsbypass/dnsbypass status   # 一样能用
  想把状态放到别处（比如项目目录只读）：
  dnsbypass --state-dir /var/lib/dnsbypass start --port 53

【故障排查】
  "sudo 起不来 / DoH 探测失败"     sudo 的 env_reset 会清掉 http_proxy。
                                   程序会自动从同 uid 进程的 /proc 里找回；
                                   也可以写进 config.toml 的 upstream_proxy，或加 --proxy。
  "绑上了但解析不动 / served=0"     多半是绑在 127.0.0.1:53（镜像模式被 Windows 吞包）。
                                   用 bind_host = "127.0.0.2"（默认已经是）。
  "刚起好却解析出假地址"            冷启动首查要 0.3–1.3s，resolv.conf 的 timeout 太小会让
                                   glibc 提前翻到第二个（明文的）nameserver。
                                   默认已给 timeout:2 attempts:1。
  "引擎挂了会断网吗"                不会：resolv.conf 里第二位仍是原解析器（LLM 兜底），
                                   只是回到被污染状态；引擎内部也有明文兜底。
  "audit 说某域名被污染但看着正常"    anycast/CDN 可能误报（如 x.com 的 Cloudflare 不同节点）。
                                   判定看整体分级；对照组只看是否命中假 IP 黑名单。
  "unbind 说备份是自产的 / 恢复不了"  这是旧版（≤0.1.0）缺陷留下的坏记录：备份里存的是程序自己
                                    生成的内容。跑 `dnsbypass repair` 恢复 WSL 原始态即可
                                    （按 WSL 默认模板重建，逐字节等于 WSL 自己生成的原文）；
                                    或在 Windows 执行 `wsl --shutdown` 让 WSL 重新生成。
                                    新版会在 `unbind`/`bind` 时自动把这种坏备份治好。
  "接管后 /etc/resolv.conf 和 /mnt/wsl/resolv.conf 内容不一样"  这是**正常且必须的**：
                                    接管期间 /etc/resolv.conf 是我们生成的真文件（指向
                                    127.0.0.2），而 /mnt/wsl/resolv.conf 保持 WSL 原文不动
                                    —— 正是它俩不同，才保证了随时能逐字节回滚。
                                    glibc 只看 /etc/resolv.conf。
  "repair 报 PermissionError / 连 sudo 都不行"  看报错里的文件名：如果是
                                    `xxx.dnsbypass.tmp`，那是旧版固定名临时文件撞上了 Linux 的
                                    `fs.protected_regular=2`（专门防"临时文件抢注"，它**不豁免
                                    root**）。直接 `rm -f` 掉那个文件再跑；新版用带 pid+随机数的
                                    临时名并会顺手清理这种垃圾，不会再撞。
  "国内网站（百度/淘宝/QQ/镜像站）变慢"  已知限制：所有查询都经代理跳去 dns.google，回来的国内
                                    CDN 节点是"海外视角"的。实测同一台机器只换 IP：淘宝 DoH 答案
                                    10.0s vs 本地答案 0.053s，QQ 3.84s vs 0.090s。修法是给国内
                                    后缀域名加"明文优先 + 假 IP 校验兜底"，当前版本尚未实施。
                                    急用可临时 `dnsbypass unbind`（代价是回到被污染状态）。
"""

COMMANDS: dict[str, str] = {
    "config": """\
config —— 显示最终生效的配置
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass [--config FILE] config [--json]

作用: 打印"程序现在真正在用的每一项设置"，以及它从哪儿来。排查"我改了配置怎么
      没生效"的第一步就是它。同时显示状态目录（state/）的实际绝对路径。

输出:
  * 生效配置的 TOML 文本（可直接另存为 config.toml）
  * --json 时额外带 config_path（来源文件，空=内置默认）与 proxy 快照

例子:
  dnsbypass config                    # 看默认值
  dnsbypass --json config | jq .state_dir
""",
    "preflight": """\
preflight —— 启动前体检（只读，不改任何东西）
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass preflight [--proxy URL] [--doh URL] [--timeout S] [--no-probe]

逐项检查并给出 ✓ / ! / ✗：
  python 版本与解释器路径      TLS 与 CA（DoH 一定要校验证书）
  代理 env / 可达性            DoH 端点真实探测（--no-probe 跳过）
  resolv.conf 现状与可写性     监听端口可绑定
  接管端口 53 可绑定           接管环回（**发包给自己**，验"绑得上 ≠ 收得到"）
  运行状态（有没有实例已在跑）

退出码: 0 = 全过；30 = 有致命项（✗）没过 —— 这时 `start` 会拒绝启动，除非 --force。

例子:
  sudo dnsbypass preflight            # 含 53 端口与环回自检（需要 root 才能验）
  dnsbypass preflight --no-probe      # 跳过网络探测，只看本地条件
""",
    "audit": """\
audit —— 污染审计（只读；给机器看的退出码）
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass audit [--proxy URL] [--doh URL] [--timeout S] [--domains a,b,c] [--json]

对每个域名同时问两条路，然后对比：
  DoH 真值  = 经代理走加密 DoH（可信）
  本机明文  = 直接问当前 resolv.conf 的解析器（会被抢答）
判定: 命中假 IP 黑名单 → 算污染；两边不一致但都不是假 IP → 只算"轻微/可能就近节点"。
分类: canary（预设会被污染的 10 个）、control（预期正常的 4 个，用来验证结论可信）、
      core（google/youtube/wikipedia，一旦污染直接判重度）。

退出码: 0 干净 / 10 轻度 / 20 重度 / 40 出错。可以直接接进 cron 或 CI。
报告落盘: <state>/audit.json

例子:
  dnsbypass audit                       # 人看的分级报告
  dnsbypass --json audit | jq .verdict  # 脚本判定
""",
    "probe": """\
probe —— 单个域名的两路对比
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass probe [--domains a,b] [--doh URL] [--proxy URL] [--json] [--timeout S]

audit 的"显微镜版"：只看你指定的域名，把 DoH 真值、本机明文、耗时一对一摆出来。
接管之后再用它，本机明文那一列其实就是"我们的引擎给的答案"。
默认域名: www.google.com

例子:
  dnsbypass probe --domains www.google.com,x.com,www.reddit.com
""",
    "run": """\
run —— 前台启动转发引擎（调试用）
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass run [--host H] [--port P] [--proxy URL] [--doh URL] [--fallback a,b]
                    [--timeout S] [--no-preflight] [--no-probe] [--force]

前台跑，Ctrl-C 退出；日志直接打在终端上。默认端口 5353（**免 sudo**，用 dig 试最方便）。
指定 --port 53 时会自动把监听地址切到 bind_host（默认 127.0.0.2），因为镜像模式下
127.0.0.1:53 被 Windows 侧占用；这个端口需要 root。

引擎干了什么:
  收明文查询 → 事务 ID 修正后回包（缓存命中）
             → 未命中就原样透传给 DoH（RFC8484；不解码、不重构，EDNS0/DNSSEC 都能过）
             → DoH 失败先按 doh_retries 重试，仍失败转明文兜底（保命优先于正确）
  缓存: 只缓存 DoH 的成功应答（RCODE=0），TTL 取上游最小 TTL 且不超过 ttl_cap。
        明文兜底的答案**不缓存** —— 它可能已经被投毒，缓存等于把污染钉住。

例子:
  dnsbypass run --port 5353 &
  dig @127.0.0.1 -p 5353 www.google.com +short
""",
    "start": """\
start —— 后台启动转发引擎（真正常用的那条）
───────────────────────────────────────────────────────────────────────────
用法: sudo dnsbypass start [--port P] [--proxy URL] [--doh URL] [--fallback a,b]
                          [--wait S] [--force] [--no-preflight] [--no-probe]

把引擎放到后台（新会话，脱离当前终端），日志写 <state>/engine.log，状态写
<state>/engine.json，父进程最多等 --wait 秒确认它真的起来了（失败会打印日志尾部）。
启动后引擎会**降权到你（SUDO_UID）的 uid**：所以 `dnsbypass stop` 不需要 sudo。

sudo 与代理: sudo 的 env_reset 会把 http_proxy/https_proxy 清掉，而 DoH 那一跳必须
  走代理。程序会自动从同 uid 进程的 /proc/<pid>/environ 里找回并显式传给子进程；
  也可以写死：config.toml 的 upstream_proxy = "http://127.0.0.1:65532"，
  或命令行 --proxy http://127.0.0.1:65532。
注意: 此时还没改 resolv.conf —— 起引擎和接管是两件事，前者不影响任何人。

例子:
  sudo dnsbypass start --port 53
  dnsbypass status && dnsbypass stop
""",
    "stop": """\
stop —— 停止后台引擎
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass stop

按 <state>/engine.json 里的 pid 发 SIGTERM（优雅退出：关 socket、写最终状态）。
因为引擎已经降权到你的 uid，通常**不需要 sudo**。
如果 resolv.conf 还指向它（已 bind），停掉之后第二位 nameserver 会接管解析 ——
不会断网，但会回到被污染的状态。要彻底还原就 unbind。

例子:
  sudo dnsbypass unbind && dnsbypass stop
""",
    "status": """\
status —— 一眼看全现状
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass status [--json]

输出:
  resolv.conf : 路径、当前 nameserver、是否可写
  引擎       : running/stopped、pid、是否真的活着、监听地址、DoH 端点
  统计       : served/hit/miss/doh_ok/doh_fail/fallback_ok/fallback_fail/malformed、缓存条数
  端口探测   : 端口要不要 root
  接管状态   : resolv.conf 是否已指向本引擎

统计每 5 秒刷一次盘；热查询命中缓存时 hit 会持续上涨、miss 不动。

例子:
  dnsbypass status
  dnsbypass --json status | jq '.stats.hit'
""",
    "bind": """\
bind —— 接管 /etc/resolv.conf（唯一会写系统文件的地方）
───────────────────────────────────────────────────────────────────────────
用法: sudo dnsbypass bind [--target FILE] [--dry-run]

做了什么（顺序很重要）:
  1. 读现状并**备份**到 <state>/resolv.conf.backup，记录原形态（符号链接？指向哪？权限？）
     —— 记录落在 <state>/bind.json，unbind 只信这份记录，不靠猜。
  2. 生成新内容: nameserver <bind_host>（默认 127.0.0.2）+ 兜底 nameserver（原来那些）
     + options（默认 timeout:2 attempts:1）。
  3. WSL 下 /etc/resolv.conf 通常是指向 /mnt/wsl/resolv.conf 的符号链接：
     **把符号链接换成真文件**。链接目标 /mnt/wsl/resolv.conf **保持原样不动** ——
     旧版会写穿过去、把 WSL 的原文覆盖掉，导致回滚无法还原；现在只额外存一份
     <state>/resolv.conf.target.backup 作双保险。
  4. 权限按原样设（一般 644 root:root）。
  5. 若当前文件已经是本程序生成的（托管中重复 bind、上次回滚没跑完），会**沿用首次记录的
     原始形态**，绝不把"原本是符号链接"这个事实弄丢。备份也不会被自产内容覆盖，
     连记录里的"首次接管时间"都会保留（重复 bind 只记一个 rebound_at）。

注意: --target 可以指向任意文件（自测用，不需要 root）；--dry-run 只算不写。
      systemd-resolved 的 stub（127.0.0.53）会被拒绝接管 —— 先把 resolved 处理好。

例子:
  sudo dnsbypass bind
  dnsbypass bind --target /tmp/fake-resolv.conf --dry-run   # 无 sudo 演练
""",
    "unbind": """\
unbind —— 回滚接管（需 root 才能写 /etc）
───────────────────────────────────────────────────────────────────────────
用法: sudo dnsbypass unbind [--target FILE] [--dry-run]

按 <state>/bind.json 恢复：原来是指向 /mnt/wsl/resolv.conf 的符号链接，
就恢复成同样的符号链接；原来是真文件，就恢复成真文件（内容取自备份），
权限/属主一并还原。**逐字节还原**（可用 md5sum 对比）。
没有记录时不会乱动，直接报错退出。

安全检查: 如果备份文件里存的竟然是程序自己生成的内容（旧版 ≤0.1.0 的缺陷会把
  "第二次 bind 时的当前内容"当成原始备份），unbind 会**拒绝执行**并指向 repair ——
  因为拿它覆盖回去等于把污染钉死、还会把符号链接弄丢。

例子:
  sudo dnsbypass unbind
  md5sum /mnt/wsl/resolv.conf        # 应与接管前一致
""",
    "repair": """\
repair —— 把 resolv.conf 恢复成 WSL 原始态（救命命令）
───────────────────────────────────────────────────────────────────────────
用法: sudo dnsbypass repair [--target FILE] [--real FILE] [--nameserver IP] [--dry-run]

什么时候用:
  * `unbind` 报"备份是程序自己生成的"（旧版缺陷留下的坏记录）；
  * 记录/备份丢了、状态目录被换过，但 /etc/resolv.conf 还是本程序写的；
  * 就是想直接放弃托管、回到没被碰过的样子。

怎么做:
  1. 优先用"真·原始备份"（<state>/resolv.conf.backup，且内容不含本程序标记）逐字节还原；
     备份不可用时按 WSL 默认模板重建（就是 `generateResolvConf = true` 时 WSL 自己写的原文）：
       # This file was automatically generated by WSL. ...
       nameserver 10.255.255.254      ← 可用 --nameserver 改
  2. 把目标文件（默认 /mnt/wsl/resolv.conf）写成上面的内容，权限 644 root:root；
  3. 把 /etc/resolv.conf 变回**指向它的符号链接**（而不是真文件）。
  幂等：重复执行结果一致，可以用 md5sum 对比。

注意: 在 Windows 执行 `wsl --shutdown` 也能达到同样效果（WSL 重启时会自己重建这两者），
      但 repair 不用重启 WSL。--dry-run 只打印将要写入的内容与来源。

例子:
  sudo dnsbypass repair --dry-run
  sudo dnsbypass repair                     # 重建 WSL 原始态
  sudo dnsbypass repair --nameserver 10.255.255.254
  md5sum /etc/resolv.conf /mnt/wsl/resolv.conf
""",
    "help": """\
help —— 中文帮助
───────────────────────────────────────────────────────────────────────────
用法: dnsbypass help              # 总览（是什么、不做什么、为何要 sudo、典型流程…）
      dnsbypass help <命令>       # 单个命令的用途/参数/副作用/例子
      dnsbypass help topics       # 所有可查的命令名

例子:
  dnsbypass help bind
  dnsbypass help start
""",
}


def render(topic: str | None = None) -> str:
    if not topic or topic.strip().lower() in {"topics", "commands", "cmds", "list"}:
        if topic:
            names = "  ".join(sorted(COMMANDS))
            return f"可查询的命令：\n  {names}\n\n用法: dnsbypass help <命令>"
        return OVERVIEW
    key = topic.strip().lower()
    if key in {"-h", "--help", "all"}:
        return OVERVIEW + "\n" + "\n".join(COMMANDS[name] for name in sorted(COMMANDS))
    if key in COMMANDS:
        return COMMANDS[key]
    names = "  ".join(sorted(COMMANDS))
    return f"没有 `{topic}` 这个命令的帮助。\n可查询：\n  {names}\n\n用法: dnsbypass help <命令>"