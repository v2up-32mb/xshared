package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/v2up-32mb/xshared/config"
	"github.com/v2up-32mb/xshared/dialer"
	"github.com/v2up-32mb/xshared/routing"
)

const (
	softLimitWait       = 100 * time.Millisecond
	dialTimeoutFallback = 15 * time.Second
)

type Server struct {
	cfg           *config.Config
	dialer        dialer.Dialer
	bypassMatcher *routing.Matcher
	userPassAuth  func(user, pass string) bool
	maxConns      int

	sem      chan struct{}
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

type Option func(*Server)

func WithBypassMatcher(m *routing.Matcher) Option {
	return func(s *Server) {
		s.bypassMatcher = m
	}
}

func WithUserPassAuth(fn func(user, pass string) bool) Option {
	return func(s *Server) {
		s.userPassAuth = fn
	}
}

func WithMaxConns(n int) Option {
	return func(s *Server) {
		s.maxConns = n
	}
}

func NewServer(cfg *config.Config, d dialer.Dialer, opts ...Option) *Server {
	s := &Server{
		cfg:    cfg,
		dialer: d,
	}
	for _, o := range opts {
		o(s)
	}
	if s.maxConns > 0 {
		s.sem = make(chan struct{}, s.maxConns)
	}
	return s
}

func (s *Server) Start() error {
	addr := s.cfg.ListenAddress
	if addr == "" {
		addr = ":8080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	go s.acceptLoop()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-time.After(0):
			default:
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()

	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		case <-time.After(softLimitWait):
			// 软等待窗口内仍无空位才拒绝（对齐 acquireProxySlot 语义）
			writeHTTPProxyResponse(c, http.StatusServiceUnavailable, "Service Unavailable", nil)
			return
		}
	}

	// handshake deadline
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(c)
	req, err := http.ReadRequest(reader)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Time{})

	if s.userPassAuth != nil {
		if !validateHTTPProxyAuth(req, s.userPassAuth) {
			writeHTTPProxyResponse(c, http.StatusProxyAuthRequired, "Proxy Authentication Required", map[string]string{
				"Proxy-Authenticate": `Basic realm="xshared"`,
			})
			return
		}
	}

	switch req.Method {
	case http.MethodConnect:
		host := req.Host
		if host == "" {
			writeHTTPProxyResponse(c, http.StatusBadRequest, "Bad Request", nil)
			return
		}
		target := ensureHTTPProxyTarget(host, "443")
		s.handleConnect(c, target, req.Host)
	default:
		target := httpProxyTargetFromRequest(req)
		if target == "" {
			writeHTTPProxyResponse(c, http.StatusBadRequest, "Bad Request", nil)
			return
		}
		first, err := buildHTTPRequestForUpstream(req)
		if err != nil {
			writeHTTPProxyResponse(c, http.StatusBadRequest, "Bad Request", nil)
			return
		}
		pending, err := readBufferedProxyBytes(reader)
		if err != nil {
			writeHTTPProxyResponse(c, http.StatusBadRequest, "Bad Request", nil)
			return
		}
		s.handleForward(c, reader, target, first, pending, req.Host)
	}
}

func (s *Server) handleConnect(c net.Conn, target, originalHost string) {
	up, err := s.dialUpstream(target, originalHost)
	if err != nil {
		writeHTTPProxyResponse(c, http.StatusBadGateway, "Bad Gateway", nil)
		return
	}
	defer up.Close()

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	pumpBidirectional(c, up)
}

func (s *Server) handleForward(c net.Conn, reader *bufio.Reader, target string, first, pending []byte, originalHost string) {
	up, err := s.dialUpstream(target, originalHost)
	if err != nil {
		writeHTTPProxyResponse(c, http.StatusBadGateway, "Bad Gateway", nil)
		return
	}
	defer up.Close()

	if _, err := up.Write(first); err != nil {
		return
	}
	if len(pending) > 0 {
		if _, err := up.Write(pending); err != nil {
			return
		}
	}
	// bidirectional pump, client side is original net.Conn
	pumpBidirectional(c, up)
}

// dialTimeout 返回拨号超时；零值/未配置时回退默认值。
func (s *Server) dialTimeout() time.Duration {
	if t := s.cfg.GetTunnelTimeout(); t > 0 {
		return t
	}
	return dialTimeoutFallback
}

func (s *Server) dialUpstream(target string, originalHost string) (net.Conn, error) {
	if s.bypassMatcher != nil && originalHost != "" {
		hostOnly := originalHost
		if h, _, err := net.SplitHostPort(originalHost); err == nil {
			hostOnly = h
		}
		targetHost := target
		if h, _, err := net.SplitHostPort(target); err == nil {
			targetHost = h
		}
		if s.bypassMatcher.Match(hostOnly, targetHost) {
			ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
			cancel()
			return conn, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
	conn, err := s.dialer.DialStream(ctx, target)
	cancel()
	return conn, err
}

func pumpBidirectional(a, b net.Conn) {
	// 任一方向 EOF 后对对端 TCP CloseWrite（半关闭），保证流式协议
	// 的 EOF 语义（对齐基线 relayBypassConnections）。
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if tcp, ok := b.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if tcp, ok := a.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wg.Wait()
}

// ---- pure functions ----

func validateHTTPProxyAuth(req *http.Request, fn func(user, pass string) bool) bool {
	auth := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	user, pass := parts[0], parts[1]
	return fn(user, pass)
}

func writeHTTPProxyResponse(c net.Conn, status int, text string, headers map[string]string) {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nConnection: close\r\n", status, text)
	for k, v := range headers {
		fmt.Fprintf(buf, "%s: %s\r\n", k, v)
	}
	buf.WriteString("\r\n")
	_, _ = c.Write(buf.Bytes())
}

func httpProxyTargetFromRequest(req *http.Request) string {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		return ""
	}
	defaultPort := "80"
	if req.URL.Scheme == "https" {
		defaultPort = "443"
	}
	return ensureHTTPProxyTarget(host, defaultPort)
}

func ensureHTTPProxyTarget(host, defaultPort string) string {
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}

func buildHTTPRequestForUpstream(req *http.Request) ([]byte, error) {
	// Avoid constant-time compare for header removal; simple clone.
	h := make(http.Header, len(req.Header))
	for k, vv := range req.Header {
		h[k] = append([]string(nil), vv...)
	}
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authorization")
	if req.Host != "" && h.Get("Host") == "" {
		h.Set("Host", req.Host)
	}

	uri := "/"
	if req.URL != nil {
		uri = req.URL.EscapedPath()
		if uri == "" {
			uri = "/"
		}
		if req.URL.RawQuery != "" {
			uri += "?" + req.URL.RawQuery
		}
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, uri)
	// 有序写出头部（http.Header.Write 按 key 排序），并处理写错误
	if err := h.Write(&buf); err != nil {
		return nil, err
	}
	buf.WriteString("\r\n")
	return buf.Bytes(), nil
}

func readBufferedProxyBytes(reader *bufio.Reader) ([]byte, error) {
	n := reader.Buffered()
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
