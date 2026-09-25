package ech

import (
	"testing"
	"time"
)

func TestNewEchManagerFromDoH(t *testing.T) {
	m := NewEchManagerFromDoH("https://1.1.1.1/dns-query", "ech.example.com", 0, 0)
	if m == nil {
		t.Fatal("期望非 nil manager")
	}
	if m.echDomain != "ech.example.com" {
		t.Errorf("echDomain = %q", m.echDomain)
	}
	if m.cacheTTL != 24*time.Hour {
		t.Errorf("默认 cacheTTL = %v, want 24h", m.cacheTTL)
	}
	if m.refreshInterval != 12*time.Hour {
		t.Errorf("默认 refreshInterval = %v, want 12h", m.refreshInterval)
	}
}

func TestNewEchManagerFromDoHEmptyServerUsesBuiltinDoH(t *testing.T) {
	m := NewEchManagerFromDoH("", "ech.example.com", 0, 0)
	if m == nil {
		t.Fatal("期望非 nil manager(空 DoH 用内置列表)")
	}
}
