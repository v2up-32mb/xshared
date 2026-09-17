// Package socks5 实现 SOCKS5 代理服务器（CONNECT + 可选 UDP ASSOCIATE）。
//
// 与基线（x-client shared/socks5）的行为差异：隧道建立由注入的
// dialer.Dialer 承担（协议编舞随各后端适配器下沉），本包只负责
// SOCKS5 协议协商、鉴权、bypass 直连分流与 UDP 帧封装。
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/v2up-32mb/xshared/config"
	"github.com/v2up-32mb/xshared/dialer"
	"github.com/v2up-32mb/xshared/dns"
	"github.com/v2up-32mb/xshared/logger"
	"github.com/v2up-32mb/xshared/routing"
)

const (
	socks5Version   = 0x05
	authNone        = 0x00
	authUserPass    = 0x02
	noAcceptable    = 0xFF
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03
	atypIPv4        = 0x01
	atypDomain      = 0x03
	atypIPv6        = 0x04

	// 隧道空闲不设生命周期：deadline 只在握手/应答阶段短暂启用，
	// 建立后由 TCP 自身语义管理（基线行为）。
	handshakeTimeout        = 10 * time.Second
	localClientWriteTimeout = 10 * time.Second
	dialTimeoutFallback     = 15 * time.Second

	// softLimitWait 并发连接数达到上限后，为突发短连接预留的等待窗口
	// （对齐 x-tunnel acquireProxySlot 语义）。
	softLimitWait = 100 * time.Millisecond

	udpReadBufSize = 64 * 1024
)

// Server SOCKS5 服务器
type Server struct {
	cfg           *config.Config
	log           *logger.Logger
	streamDialer  dialer.Dialer
	dnsCache      *dns.DNSCache
	bypassMatcher *routing.Matcher
	userPassAuth  func(user, pass string) bool
	maxConns      int
	blockedPorts  []int
	downQueueSize int
	downQueueWait time.Duration

	listener      net.Listener
	sem           chan struct{}
	activeTunnels int32

	mu     sync.Mutex
	closed bool
}

// Option 配置 SOCKS5 服务器可选项。
type Option func(*Server)

// WithBypassMatcher 配置命中后走直连（net.Dial）而非 Dialer 的路由规则。
func WithBypassMatcher(m *routing.Matcher) Option {
	return func(s *Server) { s.bypassMatcher = m }
}

// WithUserPassAuth 启用 RFC1929 用户名/密码子协商（客户端提供 0x02 方法时
// 优先选择）。fn 为凭据校验回调，实现方应使用 constant-time 比较。
// 未设置时行为与基线一致：读取方法表后恒回复 no-auth。
func WithUserPassAuth(fn func(user, pass string) bool) Option {
	return func(s *Server) { s.userPassAuth = fn }
}

// WithMaxConns 限制并发连接数；0 表示无限制。占满时在 softLimitWait 窗口内
// 软等待，仍无空位则拒绝。
func WithMaxConns(n int) Option {
	return func(s *Server) { s.maxConns = n }
}

// WithDownstreamQueue 设置 UDP 下行中转队列容量与等待（默认 64 / 2s）。
// 队列满时丢弃数据报（UDP 语义：丢包优于阻塞）。TCP 隧道由 TCP 背压管理，
// 不经过该队列。
func WithDownstreamQueue(size int, timeout time.Duration) Option {
	return func(s *Server) {
		if size > 0 {
			s.downQueueSize = size
		}
		if timeout > 0 {
			s.downQueueWait = timeout
		}
	}
}

// WithDNSCache 注入 bypass 决策所需的域名解析缓存；缺省使用系统解析器。
func WithDNSCache(dc *dns.DNSCache) Option {
	return func(s *Server) { s.dnsCache = dc }
}

// WithBlockedPorts 配置 UDP 上行拦截端口列表（例如拦截 QUIC 443），
// 命中的数据报静默丢弃；列表同时传给 dialer.UDPDialer.DialUDP。
func WithBlockedPorts(ports []int) Option {
	return func(s *Server) { s.blockedPorts = append([]int(nil), ports...) }
}

// NewServer 创建 SOCKS5 服务器。
func NewServer(cfg *config.Config, d dialer.Dialer, opts ...Option) *Server {
	s := &Server{
		cfg:           cfg,
		log:           logger.GetLogger("Socks5"),
		streamDialer:  d,
		downQueueSize: 64,
		downQueueWait: 2 * time.Second,
	}
	for _, o := range opts {
		o(s)
	}
	if s.maxConns > 0 {
		s.sem = make(chan struct{}, s.maxConns)
	}
	return s
}

// Start 启动 SOCKS5 服务器
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	s.listener = listener
	s.log.Info("监听地址: %s", s.cfg.ListenAddress)
	go s.acceptLoop()
	return nil
}

// Close 关闭服务器
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

// acceptLoop 接受连接循环
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				s.log.Warn("接受连接临时错误: %v, 1秒后重试", err)
				time.Sleep(time.Second)
				continue
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			s.log.Error("接受连接失败: %v", err)
			return
		}
		go s.handleConnection(conn)
	}
}

// handleConnection 处理连接
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	// 并发限制：softLimitWait 窗口内软等待（对齐 acquireProxySlot 语义）
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		case <-time.After(softLimitWait):
			s.log.Warn("并发连接数已达上限 (%d)，拒绝新连接", s.maxConns)
			return
		}
	}

	// 1. 认证阶段
	methods, err := s.handleAuth(clientConn)
	if err != nil {
		s.log.Debug("认证失败: %v", err)
		return
	}

	// 2. 请求阶段
	cmd, originalHost, resolvedHost, port, err := s.handleRequest(clientConn, methods)
	if err != nil {
		s.log.Debug("请求处理失败: %v", err)
		return
	}

	// 3. 分发
	switch cmd {
	case cmdConnect:
		s.createTunnel(clientConn, originalHost, resolvedHost, port)
	case cmdUDPAssociate:
		s.handleUDPAssociate(clientConn, resolvedHost, port)
	}
}

// handleAuth 处理认证；返回客户端提供的方法列表（UDP 分支需要区分来源）。
func (s *Server) handleAuth(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("读取认证头失败: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}

	nMethods := int(header[1])
	var methods []byte
	if nMethods > 0 && nMethods <= 255 {
		methods = make([]byte, nMethods)
		if _, err := io.ReadFull(conn, methods); err != nil {
			return nil, fmt.Errorf("读取认证方法失败: %w", err)
		}
	}

	switch {
	case s.userPassAuth != nil && containsSOCKS5Method(methods, authUserPass):
		// 优先选择用户名/密码子协商
		if _, err := conn.Write([]byte{socks5Version, authUserPass}); err != nil {
			return nil, err
		}
		if err := s.handleUserPassSubnegotiation(conn); err != nil {
			return nil, err
		}
	case containsSOCKS5Method(methods, authNone) || (s.userPassAuth == nil && nMethods == 0):
		if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
			return nil, err
		}
	default:
		if s.userPassAuth == nil {
			// 与基线一致：无鉴权需求时即使方法表不含 no-auth 也接受
			if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
				return nil, err
			}
			return methods, nil
		}
		_, _ = conn.Write([]byte{socks5Version, noAcceptable})
		return nil, fmt.Errorf("无可接受的认证方法")
	}
	return methods, nil
}

// handleUserPassSubnegotiation RFC1929 用户名/密码子协商
func (s *Server) handleUserPassSubnegotiation(conn net.Conn) error {
	ver := make([]byte, 2) // [VER, ULEN]
	if _, err := io.ReadFull(conn, ver); err != nil {
		return err
	}
	if ver[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("认证版本无效: %d", ver[0])
	}
	uname := make([]byte, ver[1])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if s.userPassAuth(string(uname), string(passwd)) {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}
	_, _ = conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("认证失败")
}

// handleRequest 处理请求
// 返回: 命令, 原始主机名, 解析后主机, 端口, 错误
func (s *Server) handleRequest(conn net.Conn, methods []byte) (cmd byte, originalHost, resolvedHost string, port uint16, err error) {
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", "", 0, fmt.Errorf("读取请求头失败: %w", err)
	}
	if header[0] != socks5Version {
		return 0, "", "", 0, fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}
	cmd = header[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		// BIND 及其他命令均不支持（与基线 0x07 一致）
		_, werr := conn.Write([]byte{socks5Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if werr != nil {
			return cmd, "", "", 0, fmt.Errorf("发送错误响应失败: %w", werr)
		}
		return cmd, "", "", 0, fmt.Errorf("不支持的命令: %d", cmd)
	}

	addrType := header[3]
	switch addrType {
	case atypIPv4:
		addrBuf := make([]byte, 6)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return cmd, "", "", 0, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		originalHost = fmt.Sprintf("%d.%d.%d.%d", addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3])
		resolvedHost = originalHost
		port = binary.BigEndian.Uint16(addrBuf[4:6])
		s.log.Debug("IPv4 请求: %s:%d", originalHost, port)

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return cmd, "", "", 0, fmt.Errorf("读取域名长度失败: %w", err)
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return cmd, "", "", 0, fmt.Errorf("读取域名数据失败: %w", err)
		}
		domain := string(domainBuf[:domainLen])
		port = binary.BigEndian.Uint16(domainBuf[domainLen:])
		originalHost = domain
		resolvedHost = domain
		s.log.Debug("域名请求: %s", domain)

		// DNS 预解析（仅供 bypass 决策与日志；实际连接由 Dialer 负责解析）
		if s.cfg.EnableDoH && s.dnsCache != nil {
			if ip, _, rerr := s.dnsCache.ResolveAny(domain); rerr == nil {
				s.log.Debug("DNS 解析: %s -> %s", domain, ip)
				resolvedHost = ip
			}
		}

	case atypIPv6:
		addrBuf := make([]byte, 18)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return cmd, "", "", 0, fmt.Errorf("读取 IPv6 地址失败: %w", err)
		}
		originalHost = net.IP(addrBuf[:16]).String()
		resolvedHost = originalHost
		port = binary.BigEndian.Uint16(addrBuf[16:18])
		s.log.Debug("IPv6 请求: %s:%d", originalHost, port)

	default:
		_, werr := conn.Write([]byte{socks5Version, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if werr != nil {
			return cmd, "", "", 0, fmt.Errorf("发送错误响应失败: %w", werr)
		}
		return cmd, "", "", 0, fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// IPv6 地址补方括号（基线行为）
	if ip := net.ParseIP(resolvedHost); ip != nil && ip.To4() == nil {
		resolvedHost = fmt.Sprintf("[%s]", resolvedHost)
	}

	s.log.Debug("收到代理请求 -> %s:%d (解析后: %s:%d)", originalHost, port, resolvedHost, port)
	return cmd, originalHost, resolvedHost, port, nil
}

// dialTimeout 返回拨号超时；零值/未配置时回退默认值。
func (s *Server) dialTimeout() time.Duration {
	if t := s.cfg.GetTunnelTimeout(); t > 0 {
		return t
	}
	return dialTimeoutFallback
}

// createTunnel 建立 CONNECT 隧道
func (s *Server) createTunnel(clientConn net.Conn, originalHost, resolvedHost string, port uint16) {
	if s.bypassMatcher != nil && s.bypassMatcher.Match(originalHost, resolvedHost) {
		s.createDirectTunnel(clientConn, originalHost, resolvedHost, port)
		return
	}

	// resolvedHost 对纯 IPv6 已补方括号（:389-390），此处必须双侧剥括号后重新
	// JoinHostPort；若只剥左侧会构造出 "[2001:db8::1]]:443" 畸形目标（终审 B1）
	host := strings.TrimSuffix(strings.TrimPrefix(resolvedHost, "["), "]")
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	startedAt := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
	stream, err := s.streamDialer.DialStream(ctx, targetAddr)
	cancel()
	if err != nil {
		s.log.Warn("获取连接失败: %v", err)
		_, _ = clientConn.Write([]byte{socks5Version, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// 目标已连接，回复成功
	if err := writeAllWithDeadline(clientConn, []byte{socks5Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, localClientWriteTimeout); err != nil {
		s.log.Debug("发送 SOCKS5 响应失败: %v", err)
		return
	}

	s.log.Info("新请求 -> %s:%d", originalHost, port)
	atomic.AddInt32(&s.activeTunnels, 1)
	sent, received := pumpTunnel(clientConn, stream)
	atomic.AddInt32(&s.activeTunnels, -1)

	elapsed := time.Since(startedAt)
	if sent > 0 || received > 0 {
		speedKBps := float64(sent+received) / 1024.0 / elapsed.Seconds()
		s.log.Info("请求完成 -> %s:%d | 耗时=%dms ↑%s ↓%s 速度=%.1fKB/s",
			originalHost, port, elapsed.Milliseconds(), formatBytes(sent), formatBytes(received), speedKBps)
	}
}

// pumpTunnel 双向泵：任一方向 EOF 后对对端 TCP CloseWrite（半关闭），
// 保证流式协议的 EOF 语义；返回上下行字节数。
func pumpTunnel(clientConn, stream net.Conn) (sent, received int64) {
	type transferResult struct {
		upload bool
		bytes  int64
	}
	completed := make(chan transferResult, 2)
	go func() {
		n, _ := io.Copy(stream, clientConn)
		if tcpConn, ok := stream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		completed <- transferResult{upload: true, bytes: n}
	}()
	go func() {
		n, _ := io.Copy(clientConn, stream)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		completed <- transferResult{upload: false, bytes: n}
	}()
	first := <-completed
	second := <-completed
	for _, r := range []transferResult{first, second} {
		if r.upload {
			sent = r.bytes
		} else {
			received = r.bytes
		}
	}
	return sent, received
}

// createDirectTunnel 直连绕过：matcher 命中时用本地 socket 直连目标（不走 Dialer）
func (s *Server) createDirectTunnel(clientConn net.Conn, originalHost, resolvedHost string, port uint16) {
	host := strings.TrimSuffix(strings.TrimPrefix(resolvedHost, "["), "]")
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	startedAt := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
	targetConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	cancel()
	if err != nil {
		s.log.Warn("直连绕过失败 -> %s:%d: %v", originalHost, port, err)
		_, _ = clientConn.Write([]byte{socks5Version, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	if err := writeAllWithDeadline(clientConn, []byte{socks5Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, localClientWriteTimeout); err != nil {
		s.log.Debug("发送直连 SOCKS5 响应失败: %v", err)
		return
	}

	s.log.Info("直连绕过 -> %s:%d", originalHost, port)
	atomic.AddInt32(&s.activeTunnels, 1)
	sent, received := pumpTunnel(clientConn, targetConn)
	atomic.AddInt32(&s.activeTunnels, -1)

	s.log.Info("直连完成 -> %s:%d | 耗时=%dms ↑%s ↓%s",
		originalHost, port, time.Since(startedAt).Milliseconds(), formatBytes(sent), formatBytes(received))
}

// handleUDPAssociate 处理 UDP ASSOCIATE。
// Server 拥有客户端 UDP socket、SOCKS5 UDP 帧封装与关联生命周期；
// 上游数据面由 dialer.UDPDialer 提供。
func (s *Server) handleUDPAssociate(clientConn net.Conn, resolvedHost string, port uint16) {
	ud, ok := s.streamDialer.(dialer.UDPDialer)
	if !ok {
		// 后端无 UDP 能力（例如 GCM 线协议），与基线一致回"命令不支持"
		_, _ = clientConn.Write([]byte{socks5Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		s.log.Warn("后端不支持 UDP ASSOCIATE")
		return
	}

	// 绑定客户端中转 socket：优先与 TCP 监听同主机 IP，保证应答为
	// IPv4 形式 BND.ADDR（通配时回退 IPv4 通配，避免返回 22 字节 IPv6 帧）
	bindAddr := &net.UDPAddr{IP: net.IPv4zero}
	if taddr, ok := s.listener.Addr().(*net.TCPAddr); ok && taddr.IP != nil && !taddr.IP.IsUnspecified() {
		bindAddr = &net.UDPAddr{IP: taddr.IP}
	}
	udpListener, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		s.log.Warn("绑定 UDP 中转 socket 失败: %v", err)
		_, _ = clientConn.Write([]byte{socks5Version, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	actual := udpListener.LocalAddr().(*net.UDPAddr)
	resp := []byte{socks5Version, 0x00, 0x00}
	if ip4 := actual.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, 0x04)
		resp = append(resp, actual.IP...)
	}
	resp = append(resp, byte(actual.Port>>8), byte(actual.Port))
	if _, err := clientConn.Write(resp); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout())
	defer cancel()
	channel, err := ud.DialUDP(ctx, s.blockedPorts)
	if err != nil {
		s.log.Warn("建立上游 UDP 通道失败: %v", err)
		return
	}
	defer channel.Close()

	s.log.Info("UDP ASSOCIATE 中转 -> %s", udpListener.LocalAddr())
	atomic.AddInt32(&s.activeTunnels, 1)
	defer atomic.AddInt32(&s.activeTunnels, -1)

	assoc := &udpAssociation{
		server:        s,
		clientConn:    clientConn,
		udpListener:   udpListener,
		channel:       channel,
		downQueue:     make(chan []byte, s.downQueueSize),
		downQueueWait: s.downQueueWait,
		done:          make(chan struct{}),
	}
	closeDone := make(chan struct{})
	defer close(closeDone)

	// 上行：客户端 UDP socket -> 帧解析 -> 过滤 -> 上游通道
	go assoc.uplinkLoop()
	// 下行：上游通道 -> 帧封装 -> 客户端
	go assoc.downlinkLoop()
	// TCP 控制连接存活期 = 关联生命周期：丢弃数据直到对端关闭
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		assoc.notifyDone()
	}()

	<-closeDone
	assoc.waitDone()
}

type udpAssociation struct {
	server        *Server
	clientConn    net.Conn
	udpListener   *net.UDPConn
	channel       dialer.UDPChannel
	downQueue     chan []byte
	downQueueWait time.Duration

	mu            sync.Mutex
	clientUDPAddr *net.UDPAddr
	doneOnce      sync.Once
	done          chan struct{}
}

func (a *udpAssociation) notifyDone() {
	a.doneOnce.Do(func() { close(a.done) })
}

func (a *udpAssociation) waitDone() {
	<-a.done
}

// uplinkLoop 客户端 -> 上游
func (a *udpAssociation) uplinkLoop() {
	buf := make([]byte, udpReadBufSize)
	for {
		n, addr, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			a.notifyDone()
			return
		}

		// 锁定首个客户端地址（防伪造源）
		a.mu.Lock()
		if a.clientUDPAddr == nil {
			a.clientUDPAddr = addr
		} else if a.clientUDPAddr.String() != addr.String() {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		tgt, data, err := parseSOCKS5UDPPacket(buf[:n])
		if err != nil {
			continue
		}

		// UDP 端口拦截（例如拦截 QUIC 443）
		if _, ps, perr := net.SplitHostPort(tgt); perr == nil {
			if p, aerr := strconv.Atoi(ps); aerr == nil {
				blocked := false
				for _, bp := range a.server.blockedPorts {
					if bp == p {
						blocked = true
						break
					}
				}
				if blocked {
					continue
				}
			}
		}

		if err := a.channel.Send(tgt, data); err != nil {
			a.server.log.Debug("上行发送失败: %v", err)
			a.notifyDone()
			return
		}
	}
}

// downlinkLoop 上游 -> 客户端（带下行队列与拥塞丢弃）
func (a *udpAssociation) downlinkLoop() {
	// 队列投递协程：Send 侧不阻塞上游通道
	go func() {
		for {
			target, data, ok := a.channel.ReadFrom()
			if !ok {
				a.notifyDone()
				return
			}
			clientAddr := func() *net.UDPAddr {
				a.mu.Lock()
				defer a.mu.Unlock()
				return a.clientUDPAddr
			}()
			if clientAddr == nil {
				continue
			}
			frame, err := buildSOCKS5UDPPacket(target, data)
			if err != nil {
				continue
			}
			select {
			case a.downQueue <- frame:
			case <-a.done:
				return
			case <-time.After(a.downQueueWait):
				a.server.log.Debug("UDP 下行队列拥塞，丢弃数据报 (%d bytes)", len(frame))
			}
		}
	}()

	for {
		select {
		case <-a.done:
			return
		case frame := <-a.downQueue:
			a.mu.Lock()
			addr := a.clientUDPAddr
			a.mu.Unlock()
			if addr == nil {
				continue
			}
			_ = a.udpListener.SetWriteDeadline(time.Now().Add(localClientWriteTimeout))
			if _, err := a.udpListener.WriteToUDP(frame, addr); err != nil {
				a.server.log.Debug("下行写入客户端失败: %v", err)
			}
			_ = a.udpListener.SetWriteDeadline(time.Time{})
		}
	}
}

// parseSOCKS5UDPPacket 解析 SOCKS5 UDP 数据包（RSV(2)=0, FRAG(1)=0, ATYP, ADDR, PORT, DATA）
func parseSOCKS5UDPPacket(b []byte) (string, []byte, error) {
	if len(b) < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", nil, errors.New("数据不合法")
	}
	off := 4
	var h string
	switch b[3] {
	case 0x01:
		if off+4 > len(b) {
			return "", nil, errors.New("IPv4地址长度过短")
		}
		h = net.IP(b[off : off+4]).String()
		off += 4
	case 0x03:
		if off+1 > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", nil, errors.New("域名长度不足")
		}
		h = string(b[off : off+l])
		off += l
	case 0x04:
		if off+16 > len(b) {
			return "", nil, errors.New("IPv6地址长度过短")
		}
		h = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return "", nil, errors.New("地址类型无效")
	}
	if off+2 > len(b) {
		return "", nil, errors.New("端口字段过短")
	}
	p := int(b[off])<<8 | int(b[off+1])
	off += 2

	t := fmt.Sprintf("%s:%d", h, p)
	if b[3] == 0x04 {
		t = fmt.Sprintf("[%s]:%d", h, p)
	}
	return t, b[off:], nil
}

// buildSOCKS5UDPPacket 构造 SOCKS5 UDP 数据包
func buildSOCKS5UDPPacket(target string, d []byte) ([]byte, error) {
	h, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("目标地址无效: %w", err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 0 || p > 65535 {
		return nil, errors.New("端口无效")
	}

	buf := []byte{0, 0, 0} // RSV(2), FRAG(1)
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip...)
	} else {
		if len(h) > 255 {
			return nil, errors.New("域名过长")
		}
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	buf = append(buf, d...)
	return buf, nil
}

// writeAllWithDeadline 带超时的完整写入
func writeAllWithDeadline(conn net.Conn, data []byte, timeout time.Duration) error {
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
	}
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func containsSOCKS5Method(methods []byte, want byte) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

// formatBytes 将字节数格式化为人类可读的字符串
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n2 := n; n2/unit >= unit && exp < 5; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
