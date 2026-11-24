package dns

import (
	"testing"
	"time"

	"github.com/v2up-32mb/xshared/config"
)

func TestDNSCache_SetAndGet(t *testing.T) {
	initTestLogger()
	cfg := config.DefaultConfig()
	cache := NewDNSCache(cfg, NewDoHClient(cfg))
	defer cache.Close()

	// 初始状态统计
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Size != 0 {
		t.Fatalf("expected initial stats 0, got %+v", stats)
	}

	// 未命中查找
	if ip, found := cache.Get("example.com", "A"); found || ip != "" {
		t.Fatalf("expected miss for example.com, got %v", ip)
	}

	// 写入缓存并读取
	cache.Set("example.com", "A", "93.184.216.34")
	ip, found := cache.Get("example.com", "A")
	if !found || ip != "93.184.216.34" {
		t.Fatalf("expected hit 93.184.216.34, got %v (found=%v)", ip, found)
	}

	stats = cache.GetStats()
	if stats.Hits != 1 || stats.Size != 1 {
		t.Fatalf("expected hits=1, size=1, got %+v", stats)
	}
}

func TestDNSCache_ExpirationAndCleanup(t *testing.T) {
	initTestLogger()
	cfg := config.DefaultConfig()
	cache := NewDNSCache(cfg, NewDoHClient(cfg))
	defer cache.Close()

	// 手动塞入一个已过期的条目和一个未过期的条目
	cache.mu.Lock()
	cache.cache["expired.com:A"] = &CacheEntry{
		IP:        "1.1.1.1",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	cache.cache["valid.com:A"] = &CacheEntry{
		IP:        "2.2.2.2",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	cache.mu.Unlock()

	// 执行 cleanup（使用 maps.DeleteFunc）
	cache.cleanup()

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	if _, exists := cache.cache["expired.com:A"]; exists {
		t.Errorf("expected expired.com:A to be deleted by cleanup")
	}
	if _, exists := cache.cache["valid.com:A"]; !exists {
		t.Errorf("expected valid.com:A to remain in cache")
	}
	if len(cache.cache) != 1 {
		t.Errorf("expected cache size 1, got %d", len(cache.cache))
	}
}

func TestDNSCache_HTTPS(t *testing.T) {
	initTestLogger()
	cfg := config.DefaultConfig()
	cache := NewDNSCache(cfg, NewDoHClient(cfg))
	defer cache.Close()

	rec := &HTTPSRecord{
		Priority: 1,
		Target:   "target.example.com",
		ECH:      []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	cache.SetHTTPS("example.com", rec)

	got, found := cache.GetHTTPS("example.com")
	if !found || got == nil {
		t.Fatalf("expected HTTPS record found")
	}
	if got.Priority != 1 || got.Target != "target.example.com" || len(got.ECH) != 4 {
		t.Fatalf("record mismatch: %+v", got)
	}

	ech, err := cache.GetECHConfig("example.com")
	if err != nil {
		t.Fatalf("GetECHConfig error: %v", err)
	}
	if len(ech) != 4 || ech[0] != 0xDE {
		t.Fatalf("GetECHConfig mismatch: %v", ech)
	}
}

func TestDNSCache_StatsCalculation(t *testing.T) {
	initTestLogger()
	cfg := config.DefaultConfig()
	cache := NewDNSCache(cfg, NewDoHClient(cfg))
	defer cache.Close()

	cache.Set("test.com", "A", "1.2.3.4")

	// 2 次命中
	cache.Get("test.com", "A")
	cache.Get("test.com", "A")

	// 直接原子修改 stats 测试 HitRate 计算
	cache.stats.Misses.Add(2)

	stats := cache.GetStats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("expected 2 misses, got %d", stats.Misses)
	}
	if stats.HitRate != 50.0 {
		t.Errorf("expected 50.0%% hit rate, got %f", stats.HitRate)
	}
}
