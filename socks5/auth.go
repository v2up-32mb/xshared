package socks5

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

// ParseSocks5Auth 解析 "socks5://user:pass@host" 形式的本地代理监听地址。
// 凭据非空时消费方应启用 SOCKS5 RFC1929 子协商。
func ParseSocks5Auth(addr string) (host, user, pass string, err error) {
	full := strings.TrimPrefix(addr, "socks5://")
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("地址格式错误: %s", addr)
		}
		auth := parts[0]
		host = parts[1]
		if strings.Contains(auth, ":") {
			creds := strings.SplitN(auth, ":", 2)
			user, pass = creds[0], creds[1]
		} else {
			user = auth
		}
		return host, user, pass, nil
	}
	return full, "", "", nil
}

// AuthEqual 常量时间比较（鉴权回调使用，防时序侧信道）。
func AuthEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}