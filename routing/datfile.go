package routing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

// ---- v2ray 生态数据文件（geoip.dat / geosite.dat，protobuf wire 格式）支持 ----
//
// 手写最小 wire 解码（零 protobuf 运行时依赖），仅覆盖所需消息结构：
//
//	GeoIPList { entry:1 repeated GeoIP }
//	GeoIP     { country_code:1 string; cidr:3 repeated CIDR }
//	CIDR      { ip:1 bytes; prefix:2 uint32 }
//	GeoSiteList { entry:1 repeated GeoSite }
//	GeoSite   { country_code:1 string; domain:2 repeated Domain }
//	Domain    { type:1 enum(Plain=0,Domain=1,Full=2,Regex=3); value:2 string; attribute:3 repeated string }
//
// 解析策略：跳过未知字段编号/类型（wire 兼容），attribute 忽略。

// ErrGeoDataTooLarge 数据文件超过安全上限（防解压炸弹/坏文件）
var ErrGeoDataTooLarge = fmt.Errorf("geo 数据文件超过 %dMB 上限", maxGeoFileSize>>20)

const maxGeoFileSize = 100 << 20

// geoWireField 单个 wire 字段
type geoWireField struct {
	num  int
	typ  int
	data []byte
	val  uint64
}

// geoIterFields 迭代一段消息内的顶层字段
func geoIterFields(buf []byte, fn func(geoWireField) error) error {
	i := 0
	for i < len(buf) {
		key, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			return fmt.Errorf("geo dat: 非法字段 key 偏移 %d", i)
		}
		i += n
		f := geoWireField{num: int(key >> 3), typ: int(key & 0x7)}
		switch f.typ {
		case 0: // varint
			v, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return fmt.Errorf("geo dat: 非法 varint")
			}
			f.val = v
			i += n
		case 1: // 64-bit
			if i+8 > len(buf) {
				return fmt.Errorf("geo dat: 截断 64-bit 字段")
			}
			f.val = binary.LittleEndian.Uint64(buf[i:])
			i += 8
		case 2: // length-delimited
			l, n := binary.Uvarint(buf[i:])
			if n <= 0 || i+n+int(l) > len(buf) {
				return fmt.Errorf("geo dat: 非法长度前缀")
			}
			i += n
			f.data = buf[i : i+int(l)]
			i += int(l)
		case 5: // 32-bit
			if i+4 > len(buf) {
				return fmt.Errorf("geo dat: 截断 32-bit 字段")
			}
			f.val = uint64(binary.LittleEndian.Uint32(buf[i:]))
			i += 4
		default:
			return fmt.Errorf("geo dat: 不支持的 wire 类型 %d", f.typ)
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// parseGeoIPDat 解析 geoip.dat，返回指定国家（小写）的全部 CIDR 前缀
func parseGeoIPDat(data []byte, country string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	err := geoIterFields(data, func(f geoWireField) error {
		if f.typ != 2 || f.num != 1 { // repeated GeoIP entry
			return nil
		}
		var code string
		var cidrs [][]byte
		var plens []uint64
		if err := geoIterFields(f.data, func(g geoWireField) error {
			switch {
			case g.num == 1 && g.typ == 2:
				code = string(g.data)
			case g.num == 3 && g.typ == 2: // repeated CIDR
				if err := geoIterFields(g.data, func(c geoWireField) error {
					switch {
					case c.num == 1 && c.typ == 2:
						cidrs = append(cidrs, c.data)
					case c.num == 2 && c.typ == 0:
						plens = append(plens, c.val)
					}
					return nil
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if !strings.EqualFold(code, country) {
			return nil
		}
		if len(cidrs) != len(plens) {
			return fmt.Errorf("geo dat: GeoIP 条目 ip/prefix 数量不匹配 (%d/%d)", len(cidrs), len(plens))
		}
		for i, raw := range cidrs {
			addr, ok := netip.AddrFromSlice(raw)
			if !ok {
				return fmt.Errorf("geo dat: 非法 IP 字节（%d 字节）", len(raw))
			}
			plen := int(plens[i])
			if plen < 0 || plen > addr.BitLen() {
				return fmt.Errorf("geo dat: 非法前缀长度 %d", plen)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), plen))
		}
		return nil
	})
	return prefixes, err
}

// parseGeoSiteDat 解析 geosite.dat，返回指定国家（小写）的域名规则行
// （输出与内置 geosite_cn.txt 同格式：domain:/full:/关键词原样，regexp 输出为 regexp: 前缀行）
func parseGeoSiteDat(data []byte, country string) ([]string, error) {
	var lines []string
	err := geoIterFields(data, func(f geoWireField) error {
		if f.typ != 2 || f.num != 1 { // repeated GeoSite entry
			return nil
		}
		var code string
		var domains []geoWireField
		if err := geoIterFields(f.data, func(g geoWireField) error {
			switch {
			case g.num == 1 && g.typ == 2:
				code = string(g.data)
			case g.num == 2 && g.typ == 2:
				domains = append(domains, g)
			}
			return nil
		}); err != nil {
			return err
		}
		if !strings.EqualFold(code, country) {
			return nil
		}
		for _, d := range domains {
			var dType uint64
			var value string
			if err := geoIterFields(d.data, func(x geoWireField) error {
				switch {
				case x.num == 1 && x.typ == 0:
					dType = x.val
				case x.num == 2 && x.typ == 2:
					value = string(x.data)
				}
				return nil
			}); err != nil {
				return err
			}
			if value == "" {
				continue
			}
			switch dType {
			case 0, 1: // Plain 子串 / Domain 后缀 —— matcher 语义均为 domain:
				lines = append(lines, "domain:"+value)
			case 2: // Full 精确
				lines = append(lines, "full:"+value)
			case 3: // Regex
				lines = append(lines, "regexp:"+value)
			default:
				lines = append(lines, "domain:"+value)
			}
		}
		return nil
	})
	return lines, err
}

// loadGeoFile 读取数据文件（含大小上限校验）
func loadGeoFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxGeoFileSize {
		return nil, ErrGeoDataTooLarge
	}
	return os.ReadFile(path)
}

// applyGeoFiles 用 v2ray 生态 geoip.dat/geosite.dat（country 提取，通常 "cn"）覆盖
// matcher 的对应数据组；路径为空或文件不存在时静默保留内置数据（调用方无需探存）。
// 解析失败返回错误（文件存在但损坏应显式失败，而非半猜）。
func (m *Matcher) applyGeoFiles(geoIPPath, geoSitePath, country string, bypassPrivate bool) error {
	if p := strings.TrimSpace(geoIPPath); p != "" {
		if _, err := os.Stat(p); err == nil {
			data, err := loadGeoFile(p)
			if err != nil {
				return fmt.Errorf("读取 %s: %w", p, err)
			}
			prefixes, err := parseGeoIPDat(data, country)
			if err != nil {
				return fmt.Errorf("解析 %s: %w", p, err)
			}
			// 重建 IP 桶（清空内置 CN 段；private 段重放保留）
			m.ipv4 = [33]map[netip.Addr]struct{}{}
			m.ipv6 = [129]map[netip.Addr]struct{}{}
			for i := range m.ipv4 {
				m.ipv4[i] = map[netip.Addr]struct{}{}
			}
			for i := range m.ipv6 {
				m.ipv6[i] = map[netip.Addr]struct{}{}
			}
			if bypassPrivate {
				for _, raw := range privatePrefixes {
					if err := m.addPrefix(raw); err != nil {
						return err
					}
				}
			}
			for _, pfx := range prefixes {
				if err := m.addPrefix(pfx.String()); err != nil {
					return fmt.Errorf("geoip 条目 %s: %w", pfx, err)
				}
			}
		}
	}
	if p := strings.TrimSpace(geoSitePath); p != "" {
		if _, err := os.Stat(p); err == nil {
			data, err := loadGeoFile(p)
			if err != nil {
				return fmt.Errorf("读取 %s: %w", p, err)
			}
			lines, err := parseGeoSiteDat(data, country)
			if err != nil {
				return fmt.Errorf("解析 %s: %w", p, err)
			}
			// 重置域名集合后重放（内置 geosite 数据清空）
			m.domainSuffixes = map[string]struct{}{}
			m.exactDomains = map[string]struct{}{}
			m.keywords = nil
			m.regexps = nil
			if err := m.parseDomainLines(lines); err != nil {
				return fmt.Errorf("geosite 条目: %w", err)
			}
		}
	}
	return nil
}

// parseDomainLines 按内置 txt 行格式重放域名规则（domain:/full:/regexp:/关键词）
func (m *Matcher) parseDomainLines(lines []string) error {
	for _, line := range lines {
		kind, value, found := strings.Cut(line, ":")
		if !found {
			kind, value = "domain", line
		}
		switch kind {
		case "domain":
			domain, ok := normalizeDomain(value)
			if !ok {
				return fmt.Errorf("invalid domain rule %q", line)
			}
			m.domainSuffixes[domain] = struct{}{}
		case "full":
			domain, ok := normalizeDomain(value)
			if !ok {
				return fmt.Errorf("invalid full rule %q", line)
			}
			m.exactDomains[domain] = struct{}{}
		case "regexp":
			re, err := regexp.Compile(value)
			if err != nil {
				return fmt.Errorf("invalid regexp rule %q: %w", line, err)
			}
			m.regexps = append(m.regexps, re)
		default:
			return fmt.Errorf("unsupported rule type %q", kind)
		}
	}
	return nil
}

// NewMatcherWithGeoFile 构建 matcher，可选从 v2ray 生态 geoip.dat/geosite.dat
// （protobuf 二进制）加载指定国家的规则覆盖内置 CN 数据。文件缺失时静默使用内置。
// manualRules 在数据覆盖之后追加（手动规则优先级语义与 NewMatcher 一致：后进不加权，同集判定）。
func NewMatcherWithGeoFile(bypassPrivate, bypassGeoIPCN, bypassGeoSiteCN bool, manualRules string, geoIPPath, geoSitePath string) (*Matcher, error) {
	m := &Matcher{
		domainSuffixes: make(map[string]struct{}),
		exactDomains:   make(map[string]struct{}),
	}
	// 与 NewMatcher 相同的顺序：手动规则先行（可经 "private"/"geoip:cn"/"geosite:cn" 行开启开关）
	if err := m.parseManualRules(manualRules, &bypassPrivate, &bypassGeoIPCN, &bypassGeoSiteCN); err != nil {
		return nil, err
	}
	if bypassPrivate {
		for _, raw := range privatePrefixes {
			if err := m.addPrefix(raw); err != nil {
				return nil, fmt.Errorf("parse built-in private rule %q: %w", raw, err)
			}
		}
		m.domainSuffixes["localhost"] = struct{}{}
		m.domainSuffixes["local"] = struct{}{}
	}
	if bypassGeoIPCN {
		if err := m.parseIPData(geoIPCNData); err != nil {
			return nil, fmt.Errorf("parse built-in GEOIP:CN rules: %w", err)
		}
	}
	if bypassGeoSiteCN {
		if err := m.parseDomainData(geoSiteCNData); err != nil {
			return nil, fmt.Errorf("parse built-in GEOSITE:CN rules: %w", err)
		}
	}
	// v2ray 生态数据文件覆盖（文件缺失静默保留内置；仅开关开启时有意义）
	if bypassGeoIPCN || bypassGeoSiteCN {
		if err := m.applyGeoFiles(geoIPPath, geoSitePath, "cn", bypassPrivate); err != nil {
			return nil, err
		}
	}
	return m, nil
}
