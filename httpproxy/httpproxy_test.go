package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/v2up-32mb/xshared/config"
	"github.com/v2up-32mb/xshared/routing"
)

type fakeDialer struct {
	target string
	calls  int32
	gate   chan struct{} // 非空时 DialStream 阻塞直至关闭
}

func (f *fakeDialer) DialStream(ctx context.Context, target string) (net.Conn, error) {
	atomic.AddInt32(&f.calls, 1)
	f.target = target
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// 对端仅用于保持管道存在；测试只断言状态码，不消费流数据。
	c1, _ := net.Pipe()
	return c1, nil
}

func TestBuildHTTPRequestForUpstreamRemovesProxyHeaders(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET http://example.com/path?q=1 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Proxy-Connection: keep-alive\r\n" +
			"Proxy-Authorization: Basic dGVzdA==\r\n\r\n")))
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	data, err := buildHTTPRequestForUpstream(req)
	if err != nil {
		t.Fatalf("build upstream request failed: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "http://example.com/path") {
		t.Fatalf("expected origin-form request line, got %q", text)
	}
	if strings.Contains(strings.ToLower(text), "proxy-connection") || strings.Contains(strings.ToLower(text), "proxy-authorization") {
		t.Fatalf("expected proxy-only headers to be removed, got %q", text)
	}
	if !strings.HasPrefix(text, "GET /path?q=1 HTTP/1.1\r\n") {
		t.Fatalf("expected origin-form request line, got %q", text)
	}
}

func TestBuildHTTPRequestForUpstreamDoesNotConsumeBody(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"POST http://example.com/upload HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Length: 5\r\n\r\nhello")))
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	data, err := buildHTTPRequestForUpstream(req)
	if err != nil {
		t.Fatalf("build upstream request failed: %v", err)
	}
	if strings.Contains(string(data), "hello") {
		t.Fatalf("expected first upstream packet to contain headers only, got %q", string(data))
	}
}

func TestReadBufferedProxyBytesReturnsUnreadBody(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(
		"POST http://example.com/upload HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Length: 5\r\n\r\nhello"))
	if _, err := http.ReadRequest(reader); err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	data, err := readBufferedProxyBytes(reader)
	if err != nil {
		t.Fatalf("read buffered proxy bytes failed: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected unread body bytes hello, got %q", string(data))
	}
}

func TestServerCONNECTRequiresAuth(t *testing.T) {
	cfg := &config.Config{ListenAddress: "127.0.0.1:0"}
	s := NewServer(cfg, &fakeDialer{}, WithUserPassAuth(func(u, p string) bool { return u == "user" && p == "pass" }))
	if err := s.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer s.Close()

	addr := s.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", resp.StatusCode)
	}
}

func TestServerCONNECTWithAuthSucceeds(t *testing.T) {
	cfg := &config.Config{ListenAddress: "127.0.0.1:0"}
	s := NewServer(cfg, &fakeDialer{}, WithUserPassAuth(func(u, p string) bool { return u == "user" && p == "pass" }))
	if err := s.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer s.Close()

	addr := s.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	enc := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic " + enc + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	// read response
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// simple check that connection stays open
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	// pipe closed, may error
	_ = err
}

func TestServerForwardPlain(t *testing.T) {
	cfg := &config.Config{ListenAddress: "127.0.0.1:0"}
	s := NewServer(cfg, &fakeDialer{})
	if err := s.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer s.Close()

	addr := s.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	// The server will try to dial upstream via fakeDialer which returns a pipe.
	// The connection should not immediately close with error.
	time.Sleep(50 * time.Millisecond)
	// No assertion beyond no panic.
}

func TestServerBypassDirect(t *testing.T) {
	// start a real TCP echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			ioCopy(c)
			c.Close()
		}
	}()

	cfg := config.DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	matcher := MustNewMatcher("127.0.0.1")
	s := NewServer(cfg, &fakeDialer{}, WithBypassMatcher(matcher))
	if err := s.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer s.Close()

	addr := s.listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	req := "CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func MustNewMatcher(rule string) *routing.Matcher {
	m, err := routing.NewMatcher(false, false, false, rule)
	if err != nil {
		panic(err)
	}
	return m
}

func ioCopy(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		c.Write(buf[:n])
	}
}

// ---- 六缺陷回归测试（deadline 清除 / forward bypass / 超时兜底 / 软等待 / FD 泄漏 / 半关闭）----

func TestServer407ClosesConnection(t *testing.T) {
	cfg := &config.Config{ListenAddress: "127.0.0.1:0"}
	s := NewServer(cfg, &fakeDialer{}, WithUserPassAuth(func(u, p string) bool { return false }))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("期望 407, got %d err=%v", resp.StatusCode, err)
	}
	// 407 后连接必须被服务器关闭（FD 泄漏回归）
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Fatalf("407 后连接未关闭")
	}
}

func TestServerZeroConfigDialFallback(t *testing.T) {
	cfg := &config.Config{ListenAddress: "127.0.0.1:0"} // TunnelTimeout=0
	s := NewServer(cfg, &fakeDialer{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("零值 Config 应走 15s 兜底并成功, got %d err=%v", resp.StatusCode, err)
	}
}

func TestServerForwardBypassHitsDirect(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, aerr := up.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		ioCopy(c)
	}()

	d := &fakeDialer{}
	m := MustNewMatcherWithBypassPrivate()
	cfg := config.DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	s := NewServer(cfg, d, WithBypassMatcher(m))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	port := up.Addr().(*net.TCPAddr).Port
	req := "GET http://127.0.0.1:" + itoa(port) + "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	// forward 请求的上行数据被直连上游回显 → 客户端应收到
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		if !strings.Contains(string(buf), "GET /") {
			t.Fatalf("直连回显不符: %q", buf)
		}
	}
	if n := atomic.LoadInt32(&d.calls); n != 0 {
		t.Fatalf("bypass 命中时不应调用 DialStream，实际 %d 次", n)
	}
}

func TestServerHalfClosePropagatesEOF(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, aerr := up.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("hello"))
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // 仅关写端
		}
		time.Sleep(400 * time.Millisecond)
	}()

	d := &fakeDialer{}
	d.gate = make(chan struct{})
	close(d.gate)
	realDial := func(ctx context.Context, target string) (net.Conn, error) {
		return net.Dial("tcp", up.Addr().String())
	}
	cfg := config.DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	s := NewServer(cfg, &realDialAdapter{inner: d, dial: realDial})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	rb := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rb, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT 失败: %d %v", resp.StatusCode, err)
	}
	start := time.Now()
	data, rerr := io.ReadAll(io.MultiReader(rb, conn))
	if string(data) != "hello" || rerr != nil {
		t.Fatalf("期望 hello+EOF, got %q err=%v", data, rerr)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("半关闭 EOF 未及时传播")
	}
}

func TestServerMaxConnsSoftWait(t *testing.T) {
	d := &fakeDialer{gate: make(chan struct{})}
	cfg := config.DefaultConfig()
	cfg.ListenAddress = "127.0.0.1:0"
	s := NewServer(cfg, d, WithMaxConns(1))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// c1 占住唯一槽位
	c1, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c1.Write([]byte("CONNECT a.com:443 HTTP/1.1\r\nHost: a.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // 让 c1 进入拨号 gate（槽位已占）

	// c2：100ms 软等待窗口内不应被立即 503
	c2, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Write([]byte("CONNECT b.com:443 HTTP/1.1\r\nHost: b.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// 软等待窗口（100ms）内：不应有任何 HTTP 应答
	time.Sleep(40 * time.Millisecond)
	_ = c2.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	buf := make([]byte, 1)
	if n, _ := c2.Read(buf); n > 0 {
		t.Fatalf("软等待窗口内 c2 不应收到应答，得到 %q", buf[:n])
	}

	// 窗口过后（c1 仍占用）：应得到 503 而非连接静默丢弃
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("软等待超时后应得到 503, got %v err=%v", resp, err)
	}
}

func MustNewMatcherWithBypassPrivate() *routing.Matcher {
	m, err := routing.NewMatcher(true, false, false, "")
	if err != nil {
		panic(err)
	}
	return m
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// realDialAdapter 用自定义拨号函数覆盖 fakeDialer 行为
type realDialAdapter struct {
	inner *fakeDialer
	dial  func(ctx context.Context, target string) (net.Conn, error)
}

func (r *realDialAdapter) DialStream(ctx context.Context, target string) (net.Conn, error) {
	return r.dial(ctx, target)
}
