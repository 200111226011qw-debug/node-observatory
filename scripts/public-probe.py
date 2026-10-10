#!/usr/bin/env python3
"""Probe one explicitly configured HTTP(S)/SOCKS proxy and report to Node Observatory.
Requires: python -m pip install 'requests[socks]'
Never accepts arbitrary target URLs; checks a small fixed list of public services.
"""
import argparse
import ipaddress
import json
import os
import statistics
import time
import requests

IP_ENDPOINTS = (
    "https://api.ipify.org?format=json",
    "https://1.1.1.1/cdn-cgi/trace",
)
UA = "NodeObservatory-PublicProbe/1.0"
TIMEOUT = 8


def parse_exit_ip(response):
    text = response.text.strip()
    try:
        data = response.json()
        text = str(data.get("ip", text)).strip()
    except (ValueError, AttributeError):
        for line in text.splitlines():
            if line.startswith("ip="):
                text = line[3:].strip()
                break
    try:
        ip = ipaddress.ip_address(text)
        return str(ip) if ip.is_global else None
    except ValueError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Public-source proxy probe for Node Observatory")
    ap.add_argument("--proxy", required=True, help="Proxy URL, e.g. socks5h://127.0.0.1:1080 or http://127.0.0.1:8080")
    ap.add_argument("--fingerprint", required=True, help="64-char SHA-256 fingerprint from /admin/candidates")
    ap.add_argument("--report-url", required=True, help="Worker base URL, e.g. https://nodes.example.com")
    ap.add_argument("--admin-token", default=os.getenv("ADMIN_TOKEN"), help="ADMIN_TOKEN; prefer environment variable")
    ap.add_argument("--proxycheck-key", default=os.getenv("PROXYCHECK_API_KEY"), help="Optional ProxyCheck.io API key")
    args = ap.parse_args()
    if len(args.fingerprint) != 64 or any(c not in "0123456789abcdef" for c in args.fingerprint.lower()):
        ap.error("--fingerprint must be a 64-character SHA-256 hex string")
    if not args.admin_token:
        ap.error("set --admin-token or ADMIN_TOKEN")
    if not args.report_url.startswith("https://"):
        ap.error("--report-url must use HTTPS")

    started = time.monotonic()
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": UA})
    session.proxies.update({"http": args.proxy, "https": args.proxy})
    ips, samples, details = [], [], []
    for endpoint in IP_ENDPOINTS:
        try:
            tick = time.monotonic()
            resp = session.get(endpoint, timeout=TIMEOUT)
            resp.raise_for_status()
            ip = parse_exit_ip(resp)
            if ip:
                ips.append(ip)
                samples.append((time.monotonic() - tick) * 1000)
                details.append("出口 IP 查询成功: " + endpoint.split('/')[2])
        except requests.RequestException as exc:
            details.append("出口查询失败: " + endpoint.split('/')[2] + " (" + type(exc).__name__ + ")")

    result = {"fingerprint": args.fingerprint.lower(), "method": "public-probe-v1", "checkDetails": details[:12]}
    if not ips:
        result.update({"ok": False, "reason": "所有公共出口 IP 查询均失败"})
    else:
        # Avoid treating conflicting providers as a reliable exit IP.
        unique_ips = sorted(set(ips))
        exit_ip = unique_ips[0] if len(unique_ips) == 1 else None
        result.update({"ok": True, "latencyMs": round(statistics.median(samples)), "httpLoss": 1 - len(ips) / len(IP_ENDPOINTS)})
        if exit_ip:
            result["exitIp"] = exit_ip
        else:
            result["riskReasons"] = ["公共出口查询返回不同 IP，需人工复核"]
            result["checkDetails"].append("多个出口服务返回不同 IP")

        # IP-API free endpoint: direct query about the measured public IP, not a proxy test.
        if exit_ip:
            try:
                geo = requests.get("http://ip-api.com/json/" + exit_ip + "?fields=status,country,countryCode,isp,org,as,hosting,proxy", timeout=5, headers={"User-Agent": UA})
                if geo.ok:
                    data = geo.json()
                    if data.get("status") == "success":
                        result["country"] = data.get("countryCode") or data.get("country")
                        result["isDatacenter"] = bool(data.get("hosting"))
                        if isinstance(data.get("proxy"), bool):
                            result["proxyDetected"] = data["proxy"]
                        result["checkDetails"].append("GeoIP/ASN: " + str(data.get("as") or data.get("org") or data.get("isp") or "未知")[:120])
            except (requests.RequestException, ValueError):
                result["checkDetails"].append("GeoIP 查询暂不可用")

            # Optional reputation source. Only use documented response fields; errors remain unknown.
            if args.proxycheck_key:
                try:
                    rep = requests.get("https://proxycheck.io/v2/" + exit_ip, params={"key": args.proxycheck_key, "vpn": 1, "asn": 1}, timeout=6, headers={"User-Agent": UA})
                    if rep.ok:
                        data = rep.json().get(exit_ip, {})
                        if data.get("proxy") in ("yes", "no"):
                            result["proxyDetected"] = data["proxy"] == "yes"
                        if data.get("type"):
                            result["checkDetails"].append("ProxyCheck 类型: " + str(data["type"])[:80])
                except (requests.RequestException, ValueError):
                    result["checkDetails"].append("代理信誉源暂不可用")

        # Conservative score: network reachability alone must not imply a clean IP.
        # 初筛分数必须低于发布阈值（PUBLISH_MIN_SCORE=50）：仅凭经代理拿到出口 IP 不能发布，
        # 节点仍需更完整的外部检测器（DNS/IPv6 泄漏、黑名单等）达到合格风险分后才进入订阅。
        # 有代理信誉字段时略高（仍 < 50），无则更低。
        score = 45 if isinstance(result.get("proxyDetected"), bool) else 40
        if result.get("httpLoss") is not None:
            score -= round(result["httpLoss"] * 25)
        if result.get("proxyDetected") is True:
            score -= 25
            result.setdefault("riskReasons", []).append("公共信誉源识别为代理/VPN")
        if result.get("isDatacenter") is True:
            score -= 10
            result.setdefault("riskReasons", []).append("GeoIP 数据源标记为托管/数据中心网络")
        result.setdefault("riskReasons", []).append("DNS/IPv6 泄漏与完整黑名单未验证；该分数仅为初筛")
        result["riskScore"] = max(0, min(100, score))
        result["qualityScore"] = max(0, min(100, round(100 * len(ips) / len(IP_ENDPOINTS))))
        result["checkDetails"].append("DNS/IPv6 泄漏和黑名单未由此脚本验证")
        # Do not set dnsLeak/ipv6Leak/blacklistHits when no trustworthy result exists.

    result["checkDetails"] = result.get("checkDetails", [])[:12]
    payload = {"results": [result]}
    response = requests.post(args.report_url.rstrip("/") + "/admin/health-report", json=payload,
        headers={"Authorization": "Bearer " + args.admin_token, "Content-Type": "application/json"}, timeout=10)
    response.raise_for_status()
    print(json.dumps({"probe": result, "report": response.json(), "elapsedMs": round((time.monotonic() - started) * 1000)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
