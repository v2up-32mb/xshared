// Package pipe 提供通用双向内存管道（net.Conn 语义），
// 供协议库（客户端通道池、服务端反向通道）与下游复用，
// 慢读端不会阻塞写端协程，Close 双向传播。
package pipe

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type bufferedPipe struct {
	mu      sync.Mutex
	aCh     chan []byte
	bCh     chan []byte
	aClosed bool
	bClosed bool
	aDone   chan struct{}
	bDone   chan struct{}
}

// NewBufferedPipe 创建双向缓冲内存管道（每方向 512 块缓冲，Close 双向传播）。
// 慢读端不会阻塞写端协程，供反向通道等服务端实现复用，避免拖死协议读循环。
func NewBufferedPipe() (net.Conn, net.Conn) { return newBufferedPipe() }

func newBufferedPipe() (a, b *bufferedConn) {
	p := &bufferedPipe{
		aCh:   make(chan []byte, 512),
		bCh:   make(chan []byte, 512),
		aDone: make(chan struct{}),
		bDone: make(chan struct{}),
	}
	return &bufferedConn{p: p, side: true}, &bufferedConn{p: p, side: false} // true=A 端, false=B 端
}

type bufferedConn struct {
	p       *bufferedPipe
	side    bool // true=A（写入 bCh 由 B 读），false=B
	pending []byte
}

// outCh 本端写入通道：A 写 bCh（由 B 读），B 写 aCh（由 A 读）
func (c *bufferedConn) outCh() chan []byte {
	if c.side {
		return c.p.bCh
	}
	return c.p.aCh
}

// inCh 本端读取通道：A 读 aCh（由 B 写），B 读 bCh（由 A 写）
func (c *bufferedConn) inCh() chan []byte {
	if c.side {
		return c.p.aCh
	}
	return c.p.bCh
}

// peerDone 对端关闭标志：A 等 bDone（B 关闭时置位），B 等 aDone
func (c *bufferedConn) peerDone() chan struct{} {
	if c.side {
		return c.p.bDone
	}
	return c.p.aDone
}

// selfDone 本端关闭标志：本端 Close 时关闭，对端经 peerDone 感知
func (c *bufferedConn) selfDone() chan struct{} {
	if c.side {
		return c.p.aDone
	}
	return c.p.bDone
}
func (c *bufferedConn) selfClosedFlag() *bool {
	if c.side {
		return &c.p.aClosed
	}
	return &c.p.bClosed
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	// 优先消费本端入队数据（对端 Write），随后探测对端关闭
	select {
	case data, ok := <-c.inCh():
		if !ok {
			return 0, io.EOF
		}
		c.pending = data
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	default:
	}
	select {
	case data, ok := <-c.inCh():
		if !ok {
			return 0, io.EOF
		}
		c.pending = data
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	case <-c.peerDone():
		// 对端已关闭：排空残余后 EOF
		select {
		case data, ok := <-c.inCh():
			if !ok {
				return 0, io.EOF
			}
			c.pending = data
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

func (c *bufferedConn) Write(p []byte) (int, error) {
	if *c.selfClosedFlag() {
		return 0, net.ErrClosed
	}
	// 对端已关闭：立即报错（对齐 net.Pipe 语义；竞争窗口内入队的单帧随管道回收）
	select {
	case <-c.peerDone():
		return 0, io.ErrClosedPipe
	default:
	}
	data := append([]byte(nil), p...)
	select {
	case c.outCh() <- data:
		return len(p), nil
	default:
	}
	// 队列满：限时等待（背压），对端关闭则报错
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case c.outCh() <- data:
		return len(p), nil
	case <-c.peerDone():
		return 0, io.ErrClosedPipe
	case <-timer.C:
		return 0, errors.New("buffered pipe 拥塞超时")
	}
}

func (c *bufferedConn) Close() error {
	flag := c.selfClosedFlag()
	done := c.selfDone()
	c.p.mu.Lock()
	if !*flag {
		*flag = true
		close(done)
	}
	c.p.mu.Unlock()
	return nil
}
func (c *bufferedConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *bufferedConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *bufferedConn) SetDeadline(t time.Time) error      { return nil }
func (c *bufferedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *bufferedConn) SetWriteDeadline(t time.Time) error { return nil }