// Package dialer 定义 xshared 代理实现共用的中立拨号抽象。
//
// socks5 与 httpproxy 均基于本包接口构建，协议后端（gcm / xtunnel）
// 通过实现 Dialer（可选 UDPDialer）接入，自身不感知任何代理协议细节。
package dialer

import (
	"context"
	"net"
)

// Dialer TCP 流拨号抽象。
//
// DialStream 建立 到 target（host:port，域名或 IP）的已完成
// 协议层连接准备的双向流。域名解析由实现方负责；返回的 net.Conn
// Close 时实现方负责回收流/连接资源。
type Dialer interface {
	DialStream(ctx context.Context, target string) (net.Conn, error)
}

// UDPDialer 可选 UDP 能力：实现此接口的后端才支持 SOCKS5 UDP ASSOCIATE。
// 未实现时消费方应回复"命令不支持"（0x07）。
type UDPDialer interface {
	// DialUDP 建立上游 UDP 通道；blockedPorts 为需要拦截的目标端口
	// 列表（由消费方在 SOCKS5 帧层执行过滤，实现方可用于自身策略）。
	DialUDP(ctx context.Context, blockedPorts []int) (UDPChannel, error)
}

// UDPChannel 双向 UDP 数据报通道。
type UDPChannel interface {
	// Send 发送上行数据报到 target（host:port）。
	Send(target string, data []byte) error
	// ReadFrom 读取下行数据报；ok=false 表示通道已关闭。
	ReadFrom() (target string, data []byte, ok bool)
	// Close 关闭通道。
	Close() error
}
