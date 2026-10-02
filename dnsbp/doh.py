"""DoH 客户端：把原始 DNS 报文 POST 给 DoH 端点。

要点：
  * 只走 RFC8484 的 **线格式**（application/dns-message），不做 JSON；
    一是保持"零解码透传"，二是国内 DoH 的 JSON 接口虽然干净但语义不同，不引入。
  * 出站走代理：本环境里 dns.google 的 443 直连是死的，只有经代理
    （CONNECT 带域名 → 出口端解析）才通。
  * 不解析、不重构请求报文；响应字节原样返回（ID 由调用方按需修正）。
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import wire
from .proxyenv import ProxyEnv


class DohError(RuntimeError):
    pass


@dataclass
class DohResult:
    pkt: bytes
    elapsed_ms: float
    rcode: int | None
    records: list[dict] = field(default_factory=list)

    def answers(self, rtype: int = wire.QTYPE_A) -> list[str]:
        return [r["data"] for r in self.records if r["rtype"] == rtype and r["class"] == 1]

    def describe(self) -> str:
        bits = [f"{wire.rcode_name(self.rcode)}", f"{self.elapsed_ms:.0f}ms"]
        answers = self.answers()
        if answers:
            bits.append(",".join(answers[:4]))
        return " ".join(bits)


class DohClient:
    def __init__(
        self,
        url: str,
        timeout: float = 8.0,
        proxy: ProxyEnv | None = None,
        force_proxy: bool = True,
        user_agent: str = "dnsbypass/0.1 (+local DoH forwarder)",
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.proxy = proxy
        self.force_proxy = force_proxy
        self.user_agent = user_agent
        self.host = urlsplit(url).hostname or ""
        self._opener = self._build_opener()

    # ------------------------------------------------------------ 内部

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[urllib.request.BaseHandler] = []
        mapping = self.proxy.proxy_map() if self.proxy else {}
        if mapping and self.force_proxy:
            # 显式给 httpproxy 处理：不把 no_proxy 传下去，保证这一跳一定走代理。
            handlers.append(urllib.request.ProxyHandler(mapping))
        elif mapping:
            handlers.append(urllib.request.ProxyHandler(mapping))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        context = ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=context))
        return urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------ 对外

    def query_raw(self, pkt: bytes) -> bytes:
        request = urllib.request.Request(
            self.url,
            data=pkt,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": self.user_agent,
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise DohError(f"DoH 端点返回 HTTP {exc.code}: {self.url}") from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise DohError(f"DoH 请求失败（{self.url}）: {reason}") from exc
        except ssl.SSLError as exc:
            raise DohError(f"DoH TLS 失败（{self.url}）: {exc}") from exc
        except OSError as exc:
            raise DohError(f"DoH 网络错误（{self.url}）: {exc}") from exc
        if len(body) < 12:
            raise DohError(f"DoH 返回的报文过短（{len(body)}B），不是 DNS 响应")
        if not wire.is_response(body):
            raise DohError("DoH 返回的报文不是响应（QR 位未置位）")
        return body

    def query_name(self, name: str, qtype: int = wire.QTYPE_A) -> DohResult:
        pkt = wire.build_query(name, qtype)
        started = time.monotonic()
        body = self.query_raw(pkt)
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return DohResult(
            pkt=body,
            elapsed_ms=elapsed_ms,
            rcode=wire.rcode(body),
            records=wire.parse_records(body),
        )