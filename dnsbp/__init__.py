"""dnsbypass —— 本地 DNS 去污染工具（经代理做 DoH）。

设计边界（见 README）：
  * 不安装进系统、没有 systemd 单元、默认不写任何系统文件。
  * 只有 `bind` / `unbind` 这两个显式命令会碰 resolv.conf，且带备份与回滚。
  * 出站只走 DoH（经代理）；明文仅作为保命兜底。
"""
from pathlib import Path

__version__ = "0.1.0"

PROJECT_DIR = Path(__file__).resolve().parent.parent

# 退出码契约（供脚本/自动化判断）
EXIT_OK = 0            # 干净 / 命令成功
EXIT_LIGHT = 10        # 轻度污染
EXIT_HEAVY = 20        # 重度污染
EXIT_PREFLIGHT = 30    # 预检未过（DoH 不可达 / 无代理）
EXIT_ERROR = 40        # 用法或运行时错误