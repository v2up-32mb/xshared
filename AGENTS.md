# AGENTS.md — xshared 共享基础库协作指引

面向在该仓库工作的开发者与 AI agent。采用通用的 `AGENTS.md` 命名
（取代厂商专有命名 `CLAUDE.md`），任何 agent / 编辑器 / 工具均按此约定读取。

## 项目定位

`github.com/v2up-32mb/xshared` 是 **gcm-go / xtunnel / x-client(golib) 三方共享的能力层**，
位于依赖链的**最底层**：**只提供通用基础能力，不包含任何协议/业务实现**。
下游直接依赖：`xtunnel`（核心库）与 `xtunnel-cli`（壳）等。

```
xshared(能力层: ech/DoH/SOCKS5/HTTP/dialer/pipe/routing/logger/config)
   ▲
xtunnel(核心协议库: 通道池/热表/反向隧道/中继, 仅引用 xshared 能力)
   ▲
xtunnel-cli / x-client(壳: 参数/渲染/部署)
```

## 硬性约束（不得违反）

1. **只能放"通用能力"**：ECH/DoH/DNS、SOCKS5/HTTP 服务器、拨号抽象、内存管道、路由、
   日志、配置解析等**与具体协议后端无关**的代码。**禁止**放入任何依赖 xtunnel/gcm/xclient
   的协议实现或胶水（那属于各协议库或壳）。
2. **依赖铁律**：仅允许 `golang.org/x/net` 及 Go 标准库；不得 import 任何协议后端包。
   若某能力必须引用协议后端类型，说明它放错了层：应通过接口/注入解耦后留在此层，
   或放到协议库中。
3. **能力上移方向**：若某通用能力被发现在协议库（如 xtunnel）重复实现，应**上移到此库**
   并让协议库改调（避免重复造轮子）。新增能力按 `CHANGELOG.md` 版本纪律发布。
5. **能力上移方向**：若某通用能力被发现在协议库（如 xtunnel）重复实现，应**上移到此库**
   并让协议库改调（避免重复造轮子）。新增能力按 `CHANGELOG.md` 版本纪律发布。
6. **发版铁律（最高优先级）**：**绝不未经人工确认就自行打 tag 并推送**。
   任何发版动作（打 tag、`push --tags`、创建 release）必须先向用户明确汇报版本号与发布内容并获得批准；
   提交/推送日常分支不在此限。

## 版本与发版流程

- 破坏性变更升 **minor**，修复/新增升 **patch**（0.x 阶段同理）。
- 消费方（xtunnel/xtunnel-cli/x-client/xshared 壳）独立 pin 版本，不要求同步升级。
- 发版前：`go test ./... -race` 全绿 → `CHANGELOG.md` 记入（变更 + 升级指引）→
  `README.md` 包清单/能力同步 → **向用户汇报版本号与发布内容并获批准** →
  打 tag 并 `git push origin main --tags`。

## 结构速览

| 包 | 职责 |
|---|---|
| `config` | 共享配置核心（yaml/JSON 解析保留给各端壳） |
| `dns` | DoH（多服务器 fallback）/ DNS cache / 预热列表 |
| `ech` | ECH 管理器（DoH → UDP DNS → 标准 TLS 回退链）+ 便捷工厂 |
| `logger` | 分级日志 + runtime 环形缓冲 |
| `routing` | 路由绕过 Matcher（geoip/geosite go:embed） |
| `dialer` | 中立拨号抽象（Dialer / UDPDialer） |
| `socks5` | SOCKS5 服务器 + 监听地址解析/鉴权比较工具 |
| `httpproxy` | HTTP 代理服务器 |
| `pipe` | 通用双向内存管道（net.Conn 语义） |

## 测试

```bash
go build ./... && go vet ./... && go test ./... -race
```