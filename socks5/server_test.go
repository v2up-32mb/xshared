package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/v2up-32mb/xshared/config"
	"github.com/v2up-32mb/xshared/dialer"
	"github.com/v2up-32mb/xshared/routing"
)

// ---- 测试用假实现 ----

// fakeStreamDialer 可编程的 Dialer：记录目标地址，拨号行为由 fn 决定。
type fakeStreamDialer struct {
	mu      sync.Mutex
	targets []string
	fn      func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error)
}

func (d *fakeStreamDialer) DialStream(ctx context.Context, target string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	fn := d.fn
	d.mu.Unlock()
	return fn(d, ctx, target)
}

func (d *fakeStreamDialer) dialTargets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// echoPipeDialer 返回一个回显流（net.Pipe 对端回写收到的数据）。
func echoPipeDialer() *fakeStreamDialer {
	return &fakeStreamDialer{fn: func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c1.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c2.Read(buf)
				if err != nil {
					return
				}
				if _, werr := c2.Write(buf[:n]); werr != nil {
					return
				}
			}
		}()
		return c1, nil
	}}
}

// fakeUDPChannel 内存 UDP 通道：Send 暂存，ReadFrom 原样返回（回显）。
type fakeUDPChannel struct {
	mu     sync.Mutex
	sent   []string // "target|payload"
	in     chan string
	closed chan struct{}
	once   sync.Once
}

func newFakeUDPChannel() *fakeUDPChannel {
	return &fakeUDPChannel{in: make(chan string, 16), closed: make(chan struct{})}
}

func (c *fakeUDPChannel) Send(target string, data []byte) error {
	c.mu.Lock()
	c.sent = append(c.sent, target+"|"+string(data))
	c.mu.Unlock()
	select {
	case c.in <- target + "|" + string(data):
	default:
	}
	return nil
}

func (c *fakeUDPChannel) ReadFrom() (string, []byte, bool) {
	select {
	case s := <-c.in:
		idx := indexByte(s, '|')
		return s[:idx], []byte(s[idx+1:]), true
	case <-c.closed:
		return "", nil, false
	}
}

func (c *fakeUDPChannel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func (c *fakeUDPChannel) sentItems() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.sent...)
}

// fakeUDPDialer 可选 UDP 能力的 Dialer。
type fakeUDPDialer struct {
	*fakeStreamDialer
	ch      *fakeUDPChannel
	blocked [][]int
}

func (d *fakeUDPDialer) DialUDP(ctx context.Context, blockedPorts []int) (dialer.UDPChannel, error) {
	d.mu.Lock()
	d.blocked = append(d.blocked, append([]int(nil), blockedPorts...))
	d.mu.Unlock()
	return d.ch, nil
}

// newTestServer 启动一个监听 127.0.0.1 随机端口的 SOCKS5 服务器。
func newTestServer(t *testing.T, d dialer.Dialer, opts ...Option) (*Server, string) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	s := NewServer(cfg, d, opts...)
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.listener.Addr().String()
}

// socksHandshake 完成方法协商（可选 user/pass），返回是否协商成功。
func socksHandshake(t *testing.T, conn net.Conn, methods []byte, user, pass string) {
	t.Helper()
	hdr := []byte{socks5Version, byte(len(methods))}
	if _, err := conn.Write(append(hdr, methods...)); err != nil {
		t.Fatalf("写方法表: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("读方法应答: %v", err)
	}
	switch resp[1] {
	case authNone:
		return
	case authUserPass:
		if user == "" {
			t.Fatalf("需要子协商但无凭据")
		}
		u, p := user, pass
		buf := []byte{0x01, byte(len(u))}
		buf = append(buf, u...)
		buf = append(buf, byte(len(p)))
		buf = append(buf, p...)
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("写凭据: %v", err)
		}
		sub := make([]byte, 2)
		if _, err := io.ReadFull(conn, sub); err != nil || sub[1] != 0x00 {
			t.Fatalf("子协商失败: %v %v", sub, err)
		}
	default:
		t.Fatalf("意外方法应答: %v", resp)
	}
}

// socksConnect 发送 CONNECT 并等待成功应答。
func socksConnect(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("写 CONNECT: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("CONNECT 应答非成功: %v", resp)
	}
}

// ---- CONNECT ----

func TestConnectViaFakeDialerRoundTrip(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	socksConnect(t, conn, "example.com", 443)

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回显不符: %q", buf)
	}
	if got := d.dialTargets(); len(got) != 1 || got[0] != "example.com:443" {
		t.Fatalf("DialStream 目标不符: %v", got)
	}
}

func TestConnectFailureRepliesRefused(t *testing.T) {
	d := &fakeStreamDialer{fn: func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}}
	_, addr := newTestServer(t, d)

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, 3, 'a', '.', 'c', 0, 80}
	_, _ = conn.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x05 {
		t.Fatalf("期望 0x05 拒绝，得到 %v", resp)
	}
}

// ---- bypass ----

func TestBypassRequestsUseDirectConnection(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, aerr := target.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // 回显
	}()

	// dialer 一旦被调用即测试失败（bypass 必须直连）
	d := &fakeStreamDialer{fn: func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error) {
		t.Errorf("bypass 命中时不应调用 DialStream: %s", target)
		return nil, context.Canceled
	}}
	m, merr := routing.NewMatcher(true, false, false, "") // bypass_private 命中 127.0.0.1
	if merr != nil {
		t.Fatal(merr)
	}
	_, addr := newTestServer(t, d, WithBypassMatcher(m))

	port := uint16(target.Addr().(*net.TCPAddr).Port)
	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	socksConnect(t, conn, "127.0.0.1", port)

	if _, err := conn.Write([]byte("direct")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "direct" {
		t.Fatalf("直连回显不符: %q", buf)
	}
}

// ---- 认证 ----

func TestUserPassAuthSuccess(t *testing.T) {
	called := false
	d := echoPipeDialer()
	_, addr := newTestServer(t, d, WithUserPassAuth(func(user, pass string) bool {
		called = user == "u" && pass == "p"
		return called
	}))

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone, authUserPass}, "u", "p")
	if !called {
		t.Fatalf("凭据回调未按预期收到 u/p")
	}
	socksConnect(t, conn, "example.com", 443)
}

func TestUserPassAuthFailureClosesConn(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d, WithUserPassAuth(func(user, pass string) bool {
		return false
	}))

	conn, _ := net.Dial("tcp", addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 方法协商选 0x02 → 发送错误凭据 → 服务器回 [01 01] 并关闭连接
	if _, err := conn.Write([]byte{socks5Version, 1, authUserPass}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != authUserPass {
		t.Fatalf("期望选择 userpass: %v %v", resp, err)
	}
	cred := []byte{0x01, 3, 'b', 'a', 'd', 3, 'b', 'a', 'd'}
	if _, err := conn.Write(cred); err != nil {
		t.Fatal(err)
	}
	sub := make([]byte, 2)
	if _, err := io.ReadFull(conn, sub); err != nil || sub[1] != 0x01 {
		t.Fatalf("期望子协商失败应答: %v %v", sub, err)
	}
	// 之后连接应被关闭
	if _, err := conn.Write([]byte{socks5Version, cmdConnect, 0, atypDomain, 0, 0, 80}); err == nil {
		buf := make([]byte, 8)
		if _, rerr := conn.Read(buf); rerr == nil {
			t.Fatalf("认证失败后连接未关闭")
		}
	}
}

func TestNoAcceptableMethods(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d, WithUserPassAuth(func(user, pass string) bool { return true }))

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 客户端只提供无关方法 → 0xFF
	if _, err := conn.Write([]byte{socks5Version, 1, 0x80}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != noAcceptable {
		t.Fatalf("期望 0xFF，得到 %v", resp)
	}
}

// ---- 并发限制（软等待）----

func TestMaxConnsRejectsAfterSoftWait(t *testing.T) {
	// 第一个连接持有槽位（拨号被 gate 阻塞）
	release := make(chan struct{})
	d := &fakeStreamDialer{fn: func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error) {
		<-release
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			_, _ = io.Copy(c2, c1)
		}()
		return c1, nil
	}}
	_, addr := newTestServer(t, d, WithMaxConns(1))

	c1, _ := net.Dial("tcp", addr)
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	socksHandshake(t, c1, []byte{authNone}, "", "")
	req := []byte{socks5Version, cmdConnect, 0x00, atypDomain, 3, 'a', '.', 'c', 0, 80}
	_, _ = c1.Write(req)

	// 第二个连接：槽位被占，服务器在 handleConnection 入口软等待 100ms 后
	// 拒绝并关闭 —— c2 应在方法协商阶段即被关闭（读失败）
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Write([]byte{socks5Version, 1, authNone}); err != nil {
		t.Fatalf("写入方法表: %v", err)
	}

	buf := make([]byte, 2)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(c2, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("第二个连接不应获得服务（应被软等待后拒绝关闭），得到 %v", buf)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("软等待后未关闭第二个连接")
	}
}

func TestMaxConnsServesWhenSlotFreed(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d, WithMaxConns(1))

	c1, _ := net.Dial("tcp", addr)
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(10 * time.Second))
	socksHandshake(t, c1, []byte{authNone}, "", "")

	// 第二个连接在软等待窗口内；释放第一个槽位后应获得服务
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(10 * time.Second))

	time.Sleep(20 * time.Millisecond) // 让服务器进入软等待
	_ = c1.Close()                    // 释放槽位

	socksHandshake(t, c2, []byte{authNone}, "", "")
	socksConnect(t, c2, "example.com", 443)
}

// ---- UDP ASSOCIATE ----

func TestUDPAssociateWithoutCapabilityReplies007(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d)

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	req := []byte{socks5Version, cmdUDPAssociate, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0} // +2B 端口
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x07 {
		t.Fatalf("期望 0x07 命令不支持，得到 %v", resp)
	}
}

func TestBindReplies007(t *testing.T) {
	ud := &fakeUDPDialer{fakeStreamDialer: echoPipeDialer(), ch: newFakeUDPChannel()}
	_, addr := newTestServer(t, ud)

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	req := []byte{socks5Version, cmdBind, 0x00, atypIPv4, 0, 0, 0, 0}
	_, _ = conn.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x07 {
		t.Fatalf("BIND 应回 0x07，得到 %v", resp)
	}
}

func TestUDPAssociateRelayAndBlockedPorts(t *testing.T) {
	ch := newFakeUDPChannel()
	ud := &fakeUDPDialer{fakeStreamDialer: echoPipeDialer(), ch: ch}
	_, addr := newTestServer(t, ud, WithBlockedPorts([]int{443}))

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	req := []byte{socks5Version, cmdUDPAssociate, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0} // +2B 端口
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE 应答非成功: %v", resp)
	}
	relayIP := net.IP(resp[4:8])
	relayPort := binary.BigEndian.Uint16(resp[8:10])
	relay, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: int(relayPort)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	_ = relay.SetDeadline(time.Now().Add(3 * time.Second))

	// 上行：放行端口 → 应达上游并被回显
	frame := buildUDPFrame("8.8.8.8", 53, []byte("query"))
	if _, err := relay.Write(frame); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	if _, _, err := relay.ReadFromUDP(buf); err != nil {
		t.Fatalf("未收到下行回显: %v", err)
	}
	sent := ch.sentItems()
	if len(sent) == 0 || sent[0] != "8.8.8.8:53|query" {
		t.Fatalf("上游未按预期收到: %v", sent)
	}

	// 上行：被拦截端口 → 不达上游、无回显
	blocked := buildUDPFrame("8.8.8.8", 443, []byte("quic"))
	if _, err := relay.Write(blocked); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	sent = ch.sentItems()
	for _, s := range sent {
		if s == "8.8.8.8:443|quic" {
			t.Fatalf("被拦截端口的数据到达了上游")
		}
	}
	_ = relay.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := relay.ReadFromUDP(buf); err == nil {
		t.Fatalf("被拦截端口不应产生回显")
	}

	// blockedPorts 列表应传给 DialUDP
	ud.mu.Lock()
	passed := len(ud.blocked) > 0 && len(ud.blocked[0]) == 1 && ud.blocked[0][0] == 443
	ud.mu.Unlock()
	if !passed {
		t.Fatalf("blockedPorts 未传入 DialUDP: %v", ud.blocked)
	}
}

func buildUDPFrame(host string, port uint16, payload []byte) []byte {
	frame := []byte{0, 0, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		frame = append(frame, atypIPv4)
		frame = append(frame, ip4...)
	} else {
		frame = append(frame, atypIPv6)
		frame = append(frame, ip...)
	}
	frame = binary.BigEndian.AppendUint16(frame, port)
	return append(frame, payload...)
}

// ---- TCP 半关闭 ----

func TestConnectHalfClosePropagatesEOF(t *testing.T) {
	// 真实 TCP 上游：写数据后 CloseWrite，但保持连接可读
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		c, aerr := up.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("hello"))
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // 只关写端，读端保持
		}
		time.Sleep(500 * time.Millisecond) // 期间客户端应已收到 EOF
	}()

	d := &fakeStreamDialer{fn: func(d *fakeStreamDialer, ctx context.Context, target string) (net.Conn, error) {
		return net.Dial("tcp", up.Addr().String())
	}}
	_, addr := newTestServer(t, d)

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	sport := uint16(up.Addr().(*net.TCPAddr).Port)
	socksConnect(t, conn, "127.0.0.1", sport)

	// 上游只关写端：客户端应 promptly 收到 "hello" + EOF
	start := time.Now()
	data, rerr := io.ReadAll(conn)
	elapsed := time.Since(start)
	if string(data) != "hello" || rerr != nil {
		t.Fatalf("期望 hello+EOF, 得到 %q err=%v", data, rerr)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("半关闭 EOF 未及时传播（耗时 %v）", elapsed)
	}
}

// ---- 杂项 ----

func TestUnsupportedAddressType(t *testing.T) {
	d := echoPipeDialer()
	_, addr := newTestServer(t, d)

	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	socksHandshake(t, conn, []byte{authNone}, "", "")
	_, _ = conn.Write([]byte{socks5Version, cmdConnect, 0x00, 0x99, 0, 0, 0, 0})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x08 {
		t.Fatalf("期望 0x08 地址类型不支持，得到 %v", resp)
	}
}

func TestUDPFramingRoundTrip(t *testing.T) {
	orig := buildUDPFrame("2001:db8::1", 443, []byte("x"))
	target, data, err := parseSOCKS5UDPPacket(orig)
	if err != nil {
		t.Fatal(err)
	}
	if target != "[2001:db8::1]:443" || string(data) != "x" {
		t.Fatalf("IPv6 往返不符: %q %q", target, data)
	}

	dom := []byte{0, 0, 0, atypDomain, 3, 'a', 'b', 'c', 0x01, 0xbb, 'z'}
	target, data, err = parseSOCKS5UDPPacket(dom)
	if err != nil {
		t.Fatal(err)
	}
	if target != "abc:443" || string(data) != "z" {
		t.Fatalf("域名帧解析不符: %q %q", target, data)
	}

	rebuilt, err := buildSOCKS5UDPPacket(target, data)
	if err != nil {
		t.Fatal(err)
	}
	t2, d2, err := parseSOCKS5UDPPacket(rebuilt)
	if err != nil || t2 != target || string(d2) != "z" {
		t.Fatalf("重建往返不符: %q %q %v", t2, d2, err)
	}
}
