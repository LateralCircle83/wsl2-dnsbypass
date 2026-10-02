#!/usr/bin/env bash
# 全栈最终测试（真 sudo，会动 /etc/resolv.conf，结束一定回滚）
#
# 用法: sudo tests/full-stack.sh
#
# 覆盖：起点校验 → 起引擎(53) → bind → 端到端解析(audit) → 代理那一路 →
#       引擎被杀后的保命线 → 重复 bind 安全性 → unbind+stop → 逐字节回滚校验
set -u
P="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$P"
FAIL=0
PRISTINE_MD5=ccd28ae0776549eb3926db2148a50bff
PORT=53
PROXY="${http_proxy:-http://127.0.0.1:65532}"

chk() { if [ "$2" = "$3" ]; then echo "  ✅ $1"; else echo "  ❌ $1  期望[$2] 实际[$3]"; FAIL=1; fi; }
ok()  { echo "  ✅ $1"; }
no()  { echo "  ❌ $1"; FAIL=1; }

if [ "$(id -u)" != 0 ]; then echo "请用 sudo 运行：sudo tests/full-stack.sh"; exit 2; fi

cleanup() {
  echo
  echo "== 收尾：无论如何都回滚 =="
  ./dnsbypass unbind  >/dev/null 2>&1 || ./dnsbypass repair >/dev/null 2>&1
  ./dnsbypass stop    >/dev/null 2>&1
  echo "  /etc/resolv.conf -> $(readlink /etc/resolv.conf 2>/dev/null || echo '真文件')"
  echo "  md5=$(md5sum /etc/resolv.conf | cut -d' ' -f1)"
}
trap cleanup EXIT

echo "== 0) 起点校验（应为 WSL 原始态）=="
chk "etc/resolv.conf 是指向 /mnt/wsl/resolv.conf 的符号链接" \
    "/mnt/wsl/resolv.conf" "$(readlink /etc/resolv.conf 2>/dev/null || echo '')"
chk "两者 md5 = WSL 原文" "$PRISTINE_MD5" "$(md5sum /mnt/wsl/resolv.conf | cut -d' ' -f1)"

echo "== 1) 起引擎（127.0.0.2:$PORT，启动后降权）=="
START_OUT=$(./dnsbypass start --port "$PORT" --wait 25 2>&1)
ENGINE_PID=$(./dnsbypass --json status | python3 -c 'import json,sys;print(json.load(sys.stdin).get("engine",{}).get("pid") or "")')
if [ -n "$ENGINE_PID" ] && kill -0 "$ENGINE_PID" 2>/dev/null; then
  ok "引擎 running pid=$ENGINE_PID"
else
  no "引擎没起来"; echo "$START_OUT" | tail -5 | sed 's/^/     /'
fi

echo "== 2) bind（接管 /etc/resolv.conf）=="
./dnsbypass bind >/dev/null 2>&1
chk "etc/resolv.conf 变成真文件" "regular file" "$(stat -c %F /etc/resolv.conf 2>/dev/null || echo '')"
chk "指向本引擎" "1" "$(grep -c 'nameserver 127.0.0.2' /etc/resolv.conf || true)"
chk "链接目标 /mnt/wsl/resolv.conf 未被写穿" "$PRISTINE_MD5" "$(md5sum /mnt/wsl/resolv.conf | cut -d' ' -f1)"

echo "== 3) 端到端：glibc 走我们的引擎（按 core/control/假IP 判定，canary mismatch 只记不判）=="
./dnsbypass audit >/dev/null 2>&1; RC=$?
AJ=state/audit.json
echo "     $(python3 -c "import json;print(json.load(open('$AJ'))['summary'])")"
chk "audit: 核心域名(core)无污染"   "0" "$(python3 -c "import json;print(json.load(open('$AJ'))['polluted_core'])")"
chk "audit: 对照组(control)无污染" "0" "$(python3 -c "import json;print(json.load(open('$AJ'))['polluted_control'])")"
chk "audit: 命中假 IP 数 = 0"      "0" "$(python3 -c "import json;print(json.load(open('$AJ'))['fake_total'])")"
FC=$(python3 -c "import json;print(json.load(open('$AJ'))['polluted_canary'])")
if [ "$FC" = 0 ]; then ok "audit: canary 全一致"; else echo "  ℹ audit: canary 有 $FC 个 mismatch（anycast/CDN 常见误报，不算失败；audit 退出码=$RC）"; fi
PROBE=$(./dnsbypass probe --domains www.google.com,www.youtube.com --timeout 6 2>&1)
if echo "$PROBE" | grep -q '假IP'; then no "probe 仍解析到假 IP"; echo "$PROBE" | sed 's/^/     /'; else ok "probe：本地答案没有假 IP"; fi
for d in www.google.com www.youtube.com www.wikipedia.org; do
  echo "     $d -> $(getent ahostsv4 "$d" | awk 'NR==1{print $1}')"
done

echo "== 4) 代理那一路不受影响（CONNECT 带域名，与本地 DNS 无关）=="
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -x "$PROXY" https://www.google.com/generate_204 2>/dev/null || echo 000)
chk "经代理 https://www.google.com/generate_204" "204" "$CODE"

echo "== 5) 保命线：引擎被 kill -9 后不该断网 =="
if [ -n "$ENGINE_PID" ]; then kill -9 "$ENGINE_PID" 2>/dev/null; else no "没有引擎可杀（第 1 步就失败了）"; fi
sleep 1
IP=$(getent ahostsv4 github.com | awk 'NR==1{print $1}')
if [ -n "$IP" ]; then ok "引擎死后仍能解析（github.com -> $IP，走 resolv.conf 第二位的明文兜底）"; else no "引擎死后解析失败"; fi
START_OUT=$(./dnsbypass start --port "$PORT" --wait 25 2>&1)
ENGINE_PID=$(./dnsbypass --json status | python3 -c 'import json,sys;print(json.load(sys.stdin).get("engine",{}).get("pid") or "")')
if [ -n "$ENGINE_PID" ] && kill -0 "$ENGINE_PID" 2>/dev/null; then ok "引擎重启成功 pid=$ENGINE_PID"; else no "引擎重启失败"; echo "$START_OUT" | tail -5 | sed 's/^/     /'; fi
PROBE=$(./dnsbypass probe --domains www.google.com --timeout 6 2>&1)
if echo "$PROBE" | grep -q '假IP'; then no "重启后 probe 仍见假 IP"; else ok "重启后 probe 恢复干净"; fi

echo "== 6) 重复 bind 安全性（手滑两次）=="
BEFORE=$(md5sum state/resolv.conf.backup | cut -d' ' -f1)
KIND_BEFORE=$(python3 -c 'import json;print(json.load(open("state/bind.json"))["original_kind"])')
./dnsbypass bind >/dev/null 2>&1
chk "原始备份没被覆盖" "$BEFORE" "$(md5sum state/resolv.conf.backup | cut -d' ' -f1)"
chk "原始形态仍是 symlink" "symlink" "$(python3 -c 'import json;print(json.load(open("state/bind.json"))["original_kind"])')"
chk "链接目标仍未被写穿" "$PRISTINE_MD5" "$(md5sum /mnt/wsl/resolv.conf | cut -d' ' -f1)"

echo "== 7) 回滚（unbind + stop）=="
./dnsbypass unbind >/dev/null 2>&1
./dnsbypass stop   >/dev/null 2>&1
chk "etc/resolv.conf 变回符号链接" "/mnt/wsl/resolv.conf" "$(readlink /etc/resolv.conf 2>/dev/null || echo '')"
chk "两者 md5 = WSL 原文（逐字节还原）" "$PRISTINE_MD5" "$(md5sum /etc/resolv.conf | cut -d' ' -f1)"
chk "没有残留临时文件" "0" "$(ls -1 /mnt/wsl | grep -c 'dnsbypass' || true)"
chk "没有残留监听" "0" "$(ss -lun 2>/dev/null | grep -c '127.0.0.2:53' || true)"

echo
if [ "$FAIL" = 0 ]; then echo "全部通过 ✅"; else echo "有失败项 ❌"; fi
exit "$FAIL"