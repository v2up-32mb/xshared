# xshared — 三项目共享基础库

`gcm-go` / `x-tunnel` / `x-client(golib)` 三方共同使用的 **能力层 Go 包集合**，
通过版本化 `require`（tag + GOPROXY）引用，不用 replace/submodule/vendoring。
位于依赖链最底层：只含通用基础能力，**不包含任何协议后端实现**（协议在 xtunnel）。

## 包清单（v0.1.1）

| 包 | 职责 |
|---|---|
| `config` | 共享配置核心（CLI 解析留在各端本仓） |
| `dns` | DoH（多服务器 fallback）/ DNS cache / 预热列表 |
| `ech` | ECH 管理器（DoH → UDP DNS → 标准 TLS 回退链）+ `NewEchManagerFromDoH` 工厂 |
| `logger` | 分级日志 + runtime 环形缓冲 |
| `routing` | 路由绕过 Matcher（geoip/geosite 数据 go:embed） |
| `dialer` | 中立拨号抽象（Dialer / UDPDialer），socks5 与 httpproxy 共用 |
| `socks5` | SOCKS5 代理服务器 + 监听地址解析/鉴权比较（`ParseSocks5Auth`/`AuthEqual`） |
| `httpproxy` | HTTP 代理服务器（CONNECT + forward，Dialer 注入） |
| `pipe` | 通用双向内存管道（`NewBufferedPipe`，net.Conn 语义，Close 双向传播） |

依赖铁律：仅 `golang.org/x/net` + 标准库；不依赖任何协议后端（gcm/xtunnel/xclient）。

## 常用接入

```go
// SOCKS5 监听地址解析 + 常量时间鉴权比较（壳/代理服务器使用）
host, user, pass, err := xshared_socks5.ParseSocks5Auth("socks5://user:pass@127.0.0.1:1080")
ok := xshared_socks5.AuthEqual(got, want)

// ECH 管理器（DoH → UDP DNS → 标准 TLS 回退链）
m := xshared_ech.NewEchManagerFromDoH("https://1.1.1.1/dns-query", "ech.example.com", 0, 0)

// 双向内存管道（隧道/反向通道数据面）
a, b := xshared_pipe.NewBufferedPipe()
```

协议核心库 `xtunnel` 只引用本库能力（不携带实现），详见 `xtunnel` 仓库 AGENTS.md。

## 版本纪律（0.x）

- 破坏性变更升 **minor**，修复/新增升 **patch**
- 消费方（三仓）独立 pin 版本，不要求同步升级
- 逐版本变更与升级指引见 `CHANGELOG.md`

## 开发

```bash
go build ./... && go vet ./... && go test ./... -race
```