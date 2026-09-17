package routing

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// 手编 protobuf wire 字节构造测试数据（v2ray router.GeoIPList / GeoSiteList 结构）

func wireTag(num, typ int) []byte {
	b := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(b, uint64(num)<<3|uint64(typ))
	return b[:n]
}

func wireBytes(num int, data []byte) []byte {
	out := wireTag(num, 2)
	var l [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(l[:], uint64(len(data)))
	out = append(out, l[:n]...)
	return append(out, data...)
}

func wireVarint(num int, v uint64) []byte {
	out := wireTag(num, 0)
	var l [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(l[:], v)
	return append(out, l[:n]...)
}

func wireString(num int, s string) []byte { return wireBytes(num, []byte(s)) }

func buildGeoIPDat(t *testing.T) []byte {
	t.Helper()
	// CIDR{ip=2001:db8::1? 不——用 1.2.3.0/24 与 203.0.113.0/24（TEST-NET-3）}
	mkCIDR := func(ip string, plen uint32) []byte {
		addr := netip.MustParseAddr(ip)
		out := wireBytes(1, addr.AsSlice())
		out = append(out, wireVarint(2, uint64(plen))...)
		return out
	}
	mkGeoIP := func(code string, cidrs ...[]byte) []byte {
		out := wireString(1, code)
		for _, c := range cidrs {
			out = append(out, wireBytes(3, c)...)
		}
		return out
	}
	list := wireBytes(1, mkGeoIP("cn", mkCIDR("1.2.3.0", 24), mkCIDR("2001:db8::", 32)))
	list = append(list, wireBytes(1, mkGeoIP("us", mkCIDR("8.8.8.0", 24)))...)
	return list
}

func buildGeoSiteDat(t *testing.T) []byte {
	t.Helper()
	mkDomain := func(t uint64, v string) []byte {
		out := wireVarint(1, t)
		return append(out, wireString(2, v)...)
	}
	mkGeoSite := func(code string, domains ...[]byte) []byte {
		out := wireString(1, code)
		for _, d := range domains {
			out = append(out, wireBytes(2, d)...)
		}
		return out
	}
	list := wireBytes(1, mkGeoSite("cn",
		mkDomain(1, "example-cn.com"), // Domain 后缀
		mkDomain(2, "exact-cn.org"),   // Full
		mkDomain(0, "subcn"),          // Plain 子串
	))
	list = append(list, wireBytes(1, mkGeoSite("us", mkDomain(1, "example-us.com")))...)
	return list
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGeoIPDatParsing(t *testing.T) {
	p := writeTemp(t, "geoip.dat", buildGeoIPDat(t))
	prefixes, err := parseGeoIPDat(mustRead(t, p), "cn")
	if err != nil {
		t.Fatalf("parseGeoIPDat: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}
	if prefixes[0].String() != "1.2.3.0/24" || prefixes[1].String() != "2001:db8::/32" {
		t.Fatalf("prefixes = %v", prefixes)
	}
}

func TestGeoSiteDatParsing(t *testing.T) {
	p := writeTemp(t, "geosite.dat", buildGeoSiteDat(t))
	lines, err := parseGeoSiteDat(mustRead(t, p), "cn")
	if err != nil {
		t.Fatalf("parseGeoSiteDat: %v", err)
	}
	want := []string{"domain:example-cn.com", "full:exact-cn.org", "domain:subcn"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("lines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestNewMatcherWithGeoFileOverridesBuiltin(t *testing.T) {
	geoIP := writeTemp(t, "geoip.dat", buildGeoIPDat(t))
	geoSite := writeTemp(t, "geosite.dat", buildGeoSiteDat(t))

	m, err := NewMatcherWithGeoFile(true, true, true, "", geoIP, geoSite)
	if err != nil {
		t.Fatalf("NewMatcherWithGeoFile: %v", err)
	}
	// dat 中的 CN 段生效
	if !m.Match("1.2.3.4", "1.2.3.4") {
		t.Fatal("dat CN 段 1.2.3.0/24 未生效")
	}
	if !m.Match("2001:db8::1", "2001:db8::1") {
		t.Fatal("dat CN IPv6 段未生效")
	}
	// 内置 CN 段被覆盖（8.140.0.0/24 属内置阿里云段，dat 中不存在）
	if m.Match("8.140.1.1", "8.140.1.1") {
		t.Fatal("内置 CN 段未被 dat 覆盖")
	}
	// private 段保留
	if !m.Match("192.168.1.1", "192.168.1.1") {
		t.Fatal("private 段在 dat 覆盖后丢失")
	}
	// geosite dat 生效
	if !m.Match("a.example-cn.com", "a.example-cn.com") {
		t.Fatal("dat geosite 后缀未生效")
	}
	if !m.Match("exact-cn.org", "exact-cn.org") {
		t.Fatal("dat geosite full 未生效")
	}
	// 非 CN 国家条目不加载
	if m.Match("example-us.com", "example-us.com") {
		t.Fatal("us 条目不应加载")
	}
}

func TestNewMatcherWithGeoFileMissingFilesFallsBack(t *testing.T) {
	// 文件不存在 → 静默回退内置（不报错）
	m, err := NewMatcherWithGeoFile(false, true, true, "", "/nonexistent/geoip.dat", "/nonexistent/geosite.dat")
	if err != nil {
		t.Fatalf("missing files should not error: %v", err)
	}
	if !m.Match("114.114.114.114", "114.114.114.114") {
		t.Fatal("内置 CN 数据未生效（回退失败）")
	}
	if !m.Match("baidu.com", "baidu.com") {
		t.Fatal("内置 geosite 数据未生效（回退失败）")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
