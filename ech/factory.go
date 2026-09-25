package ech

import (
	"strings"
	"time"

	"github.com/v2up-32mb/xshared/config"
	"github.com/v2up-32mb/xshared/dns"
)

// NewEchManagerFromDoH 便捷工厂：由 DoH 服务地址与 ECH 域名直接构造共享 ECH 管理器
// （DoH 多服务器 fallback 优先，失败回退 UDP DNS，再回退标准 TLS）。
// dnsServer 为空时使用内置备用 DoH 列表。
func NewEchManagerFromDoH(dnsServer, echDomain string, cacheTTL, refreshInterval time.Duration) *EchManager {
	shared := config.DefaultConfig()
	shared.EnableDoH = true
	if s := strings.TrimSpace(dnsServer); s != "" {
		shared.DoHUrl = s
	}
	return NewEchManager(dns.NewDoHClient(shared), echDomain, cacheTTL, refreshInterval)
}
