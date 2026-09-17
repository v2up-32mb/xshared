# xshared — 三项目共享基础库

`gcm-go` / `x-tunnel` / `x-client(golib)` 三方共同使用的 Go 包集合，
通过版本化 `require`（tag + GOPROXY）引用，不用 replace/submodule/vendoring。

## 包清单（v0.1）

| 包 | 职责 |
|---|---|
| `config` | 共享配置核心（CLI 解析留在各端本仓） |
| `dns` | DoH（多服务器 fallback）/ DNS cache / 预热列表 |
| `ech` | ECH 管理器（DoH → UDP DNS → 标准 TLS 回退链） |
| `logger` | 分级日志 + runtime 环形缓冲 |
| `routing` | 路由绕过 Matcher（geoip/geosite 数据 go:embed） |
| `dialer` | 中立拨号抽象（Dialer / UDPDialer），socks5 与 httpproxy 共用 |
| `socks5` | SOCKS5 代理服务器（CONNECT + 可选 UDP ASSOCIATE，Dialer 注入） |
| `httpproxy` | HTTP 代理服务器（CONNECT + forward，Dialer 注入） |

依赖铁律：仅 `golang.org/x/net`；不依赖任何协议后端（gcm/xtunnel/xclient）。

## 版本纪律（0.x）

- 破坏性变更升 **minor**，修复/新增升 **patch**
- 消费方（三仓）独立 pin 版本，不要求同步升级

## 开发

```bash
go build ./... && go vet ./... && go test ./... -race
```
