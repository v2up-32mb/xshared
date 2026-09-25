# CHANGELOG — xshared 共享基础库

记录 `github.com/v2up-32mb/xshared` 各版本变更与消费方升级指引。
版本语义：破坏性变更升 **minor**，修复/新增升 **patch**（0.x 阶段同理）。

---

## v0.1.1 — 2026-09-26

**Added**

- **`socks5` 新增 `ParseSocks5Auth` / `AuthEqual`**：SOCKS5 监听地址解析
  （`socks5://user:pass@host`，按首个 @ 分割）与常量时间鉴权比较，
  自 xtunnel（协议核心库）上移，供各消费方壳复用。新增单测。
- **`ech` 新增便捷工厂 `NewEchManagerFromDoH(dnsServer, echDomain, cacheTTL, refreshInterval)`**：
  由 DoH 地址与 ECH 域名直接构造共享 ECH 管理器（DoH → UDP DNS → 标准 TLS 回退链），
  空 dnsServer 使用内置备用 DoH 列表；自 xtunnel 装配胶水（原 `ech_bridge.go`）泛化上移。新增单测。
- **新增 `pipe` 包**：`NewBufferedPipe() (net.Conn, net.Conn)` 通用双向内存管道
  （每方向 512 块缓冲、Close 双向传播、慢读端不阻塞写端），客户端/服务端共用；
  自 xtunnel 上移，测试一并迁移（echo / 大包 / Close 传播 / 并发流）。

**升级指引**

- 纯新增，无破坏性变更；消费方可直接 `go get github.com/v2up-32mb/xshared@v0.1.1`。
- xtunnel（做 "仅核心协议" 收敛）与各壳可改用：
  - `xtunnel.ParseSocks5Auth/AuthEqual` → `xshared/socks5` 同名函数
  - 自定义 ECH 装配 → `xshared/ech.NewEchManagerFromDoH`
  - `xtunnel.NewBufferedPipe` → `xshared/pipe.NewBufferedPipe`

---

## v0.1.0 — 2026-09-25

**初始版本**

- 三方（gcm-go / x-tunnel / x-client golib）共享基础库，tag + GOPROXY 版本化引用。
- 包：`config`（共享配置核心）、`dns`（DoH 多服务器 fallback / DNS cache）、
  `ech`（ECH 管理器回退链）、`logger`（分级日志）、`routing`（geoip/geosite 路由 Matcher）、
  `dialer`（中立拨号抽象）、`socks5`（SOCKS5 服务器）、`httpproxy`（HTTP 代理服务器）。
- 依赖铁律：仅 `golang.org/x/net`，不依赖任何协议后端。