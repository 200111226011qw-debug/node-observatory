import test from "node:test";
import assert from "node:assert/strict";
import { loadWorker, b64, b64url, UUID } from "./harness.mjs";

const w = await loadWorker();
const { parseNode, extractNodes, serializeClash } = w;

test("ss: SIP002（base64url 用户信息）", () => {
  const p = parseNode(`ss://${b64url("aes-256-gcm:pa:ss")}@203.0.113.9:8388#my%20node`);
  assert.deepEqual([p.type, p.server, p.port, p.cipher, p.password, p.name], ["ss", "203.0.113.9", 8388, "aes-256-gcm", "pa:ss", "my node"]);
});
test("ss: 旧格式 base64(method:pass@host:port)", () => {
  const p = parseNode(`ss://${b64("chacha20-ietf-poly1305:pw@example.org:443")}#legacy`);
  assert.equal(p.server, "example.org"); assert.equal(p.cipher, "chacha20-ietf-poly1305");
});
test("ss: SS2022 明文 method:key（百分号编码）", () => {
  const key = Buffer.alloc(32, 7).toString("base64");
  const p = parseNode(`ss://2022-blake3-aes-256-gcm:${encodeURIComponent(key)}@198.51.100.7:9000#x`);
  assert.equal(p.password, key);
});
test("ss: 带插件 / 老旧流加密 → 拒收", () => {
  assert.equal(parseNode(`ss://${b64url("aes-256-gcm:p")}@203.0.113.9:8388?plugin=obfs-local%3Bobfs%3Dhttp#x`), null);
  assert.equal(parseNode(`ss://${b64url("rc4-md5:p")}@203.0.113.9:8388#x`), null);
});
test("vmess: ws+tls 正常转换；kcp / http 伪装 → 拒收", () => {
  const ok = { v: "2", ps: "hk-1", add: "vm.example.com", port: "443", id: UUID, aid: "0", scy: "auto", net: "ws", host: "h.example.com", path: "/ws", tls: "tls", sni: "vm.example.com" };
  const p = parseNode("vmess://" + b64(JSON.stringify(ok)));
  assert.equal(p.network, "ws"); assert.equal(p["ws-opts"].headers.Host, "h.example.com"); assert.equal(p.tls, true);
  assert.equal(parseNode("vmess://" + b64(JSON.stringify({ ...ok, net: "kcp" }))), null);
  assert.equal(parseNode("vmess://" + b64(JSON.stringify({ ...ok, net: "tcp", type: "http" }))), null);
});
test("vless: reality 需要 pbk；tls 正常；IPv6 去掉方括号", () => {
  const base = `vless://${UUID}@vl.example.com:443?security=reality&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision`;
  assert.equal(parseNode(base), null);
  const p = parseNode(base + "&pbk=PUBKEY&sid=ab12#r");
  assert.deepEqual(p["reality-opts"], { "public-key": "PUBKEY", "short-id": "ab12" });
  const v6 = parseNode(`vless://${UUID}@[2606:4700:4700::1111]:443?security=tls&sni=a.example.com#v6`);
  assert.equal(v6.server, "2606:4700:4700::1111");
});
test("vless: 明文（security=none）与 trojan allowInsecure 被标记为 insecure", () => {
  assert.equal(parseNode(`vless://${UUID}@vl.example.com:8080?security=none#p`).insecure, true);
  assert.equal(parseNode("trojan://pw@tj.example.com:443?allowInsecure=1#t").insecure, true);
  assert.equal(parseNode("trojan://pw@tj.example.com:443?sni=tj.example.com#t").insecure, undefined);
});
test("不支持的传输（kcp/httpupgrade）→ 拒收，而不是导出成 tcp", () => {
  assert.equal(parseNode(`vless://${UUID}@vl.example.com:443?security=tls&type=kcp#k`), null);
  assert.equal(parseNode(`vless://${UUID}@vl.example.com:443?security=tls&type=httpupgrade#k`), null);
});
test("vless: flow 白名单仅放行 vision 系；老式 flow 拒收", () => {
  const base = `vless://${UUID}@vl.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY&sid=ab12`;
  assert.equal(parseNode(base + "&flow=xtls-rprx-vision#r").flow, "xtls-rprx-vision");
  assert.equal(parseNode(base + "&flow=xtls-rprx-vision-udp443#r").flow, "xtls-rprx-vision-udp443");
  assert.equal(parseNode(base + "&flow=xtls-rprx-direct#r"), null);
  assert.equal(parseNode(base + "&flow=xtls-rprx-origin#r"), null);
});
test("IPv6 特殊前缀（Teredo/NAT64/ORCHID/discard-only）→ 非公网；压缩公网地址仍判公网", () => {
  for (const host of ["2001:0000::1", "2001::1", "2001:db8::1", "64:ff9b::1", "64:ff9b:1::192.168.0.1", "2001:10::1", "2001:20::1", "100::1"])
    assert.equal(w.isPublicHost(host), false, host);
  assert.equal(w.isPublicHost("2606::1"), true);                    // 第一段后直接 :: 压缩，不能误判
  assert.equal(w.isPublicHost("2606:4700:4700::1111"), true);
});
test("私网/保留地址、危险端口、奇怪主机名 → 拒收", () => {
  for (const host of ["127.0.0.1", "0.0.0.0", "10.1.2.3", "169.254.169.254", "172.20.0.1", "192.168.1.1", "100.64.0.1", "224.0.0.1",
    "localhost", "intranet.local", "nas.lan", "singlelabel", "0x7f.1", "2130706433", "010.1.1.1", "fd00::1", "fe80::1", "::1", "::ffff:127.0.0.1"]) {
    assert.equal(w.isPublicHost(host), false, host);
  }
  for (const host of ["example.com", "203.0.113.9", "2606:4700:4700::1111", "a-b.c-d.io"]) assert.equal(w.isPublicHost(host), true, host);
  assert.equal(parseNode(`trojan://pw@tj.example.com:3306#t`), null);
  assert.equal(parseNode(`trojan://pw@tj.example.com:25#t`), null);
});
test("extractNodes: 去重、剔除 wss:// 误匹配、统计拒收", () => {
  const good = `trojan://pw@tj.example.com:443#a`;
  const text = `${good}\n${good}\nwss://cdn.example.com/path\ntrojan://pw@127.0.0.1:443#bad\ntrojan://pw@tj.example.com:443?allowInsecure=1#insecure`;
  const r = extractNodes(text, {});
  assert.equal(r.nodes.length, 1); assert.equal(r.rejected, 2);
  assert.equal(extractNodes(text, { allowInsecure: true }).nodes.length, 2);
});
test("extractNodes: 整体 base64 订阅文件", () => {
  const list = [`trojan://pw@tj.example.com:443#a`, `vless://${UUID}@vl.example.com:443?security=tls#b`].join("\n");
  assert.equal(extractNodes(b64(list)).nodes.length, 2);
  assert.equal(extractNodes("just some readme text without nodes at all, definitely not base64!").nodes.length, 0);
});
test("同一节点不同名称 → 同一去重键", () => {
  const a = parseNode("trojan://pw@tj.example.com:443?sni=x.com#one"), b = parseNode("trojan://pw@TJ.example.com:443?sni=x.com#two");
  assert.equal(w.canonicalKey(a), w.canonicalKey(b));
});
test("serializeClash: 输出是可解析的结构，数组/空对象/重名都正确", () => {
  const ps = [
    parseNode(`vless://${UUID}@vl.example.com:443?security=tls&type=ws&path=%2Fp&alpn=h2,http/1.1#same`),
    parseNode(`trojan://pw@tj.example.com:443?allowInsecure=1#same`)
  ];
  ps[1].name = ps[0].name;   // 模拟重名（实际由 uniqueName 处理）
  const y = serializeClash(ps);
  assert.match(y, /alpn:\n\s+- "h2"\n\s+- "http\/1.1"/);
  assert.match(y, /skip-cert-verify: true/);
  assert.doesNotMatch(y, /insecure:/);
  assert.equal(serializeClash([]).includes("proxies: []"), true);
});
