package socks5

import "testing"

// 语义继承自 xtunnel.ParseSocks5Auth：按首个 @ 分割（密码不含 @）。
func TestParseSocks5Auth(t *testing.T) {
	cases := []struct {
		name       string
		addr       string
		host, u, p string
	}{
		{"仅主机", "socks5://127.0.0.1:1080", "127.0.0.1:1080", "", ""},
		{"用户+密码", "socks5://user:pass@127.0.0.1:1080", "127.0.0.1:1080", "user", "pass"},
		{"仅用户", "socks5://user@127.0.0.1:1080", "127.0.0.1:1080", "user", ""},
		{"host含@按首@@", "socks5://u:p@x@y:1080", "x@y:1080", "u", "p"},
		{"多@按首@分割", "socks5://a@b@c", "b@c", "a", ""},
		{"非socks5前缀原样", "127.0.0.1:1080", "127.0.0.1:1080", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, u, p, err := ParseSocks5Auth(tc.addr)
			if err != nil {
				t.Fatalf("ParseSocks5Auth(%q) 错误: %v", tc.addr, err)
			}
			if host != tc.host || u != tc.u || p != tc.p {
				t.Errorf("ParseSocks5Auth(%q) = %q/%q/%q, want %q/%q/%q", tc.addr, host, u, p, tc.host, tc.u, tc.p)
			}
		})
	}
}

func TestAuthEqual(t *testing.T) {
	if !AuthEqual("user", "user") || !AuthEqual("", "") {
		t.Error("相等应 true")
	}
	if AuthEqual("user", "pass") || AuthEqual("user", "userx") {
		t.Error("不等应 false")
	}
	if AuthEqual("abc", "ab") || AuthEqual("ab", "abc") {
		t.Error("长度不等应 false")
	}
}
