package config

import "testing"

func TestCatalogLimitFromEnv(t *testing.T) {
	t.Setenv("KEEP_DATABASE_URL", "postgres://keep@127.0.0.1/keep")
	c, err := FromEnv()
	if err != nil || c.CatalogRatePerMinute != 0 || c.CatalogBurst != 0 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	t.Setenv("KEEP_CATALOG_RATE_PER_MINUTE", "120")
	t.Setenv("KEEP_CATALOG_BURST", "7")
	c, err = FromEnv()
	if err != nil || c.CatalogRatePerMinute != 120 || c.CatalogBurst != 7 {
		t.Fatalf("set: %+v %v", c, err)
	}
	for _, bad := range []string{"0", "-3", "many", "1.5"} {
		t.Setenv("KEEP_CATALOG_BURST", bad)
		if _, err := FromEnv(); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestTrustedProxiesFromEnv(t *testing.T) {
	t.Setenv("KEEP_DATABASE_URL", "postgres://keep@127.0.0.1/keep")
	c, err := FromEnv()
	if err != nil || len(c.TrustedProxies) != 0 {
		t.Fatalf("default: %v %v", c.TrustedProxies, err)
	}
	t.Setenv("KEEP_TRUSTED_PROXIES", " 127.0.0.1/32, 10.1.2.3/8 ,::1/128")
	c, err = FromEnv()
	if err != nil || len(c.TrustedProxies) != 3 || c.TrustedProxies[0].String() != "127.0.0.1/32" ||
		c.TrustedProxies[1].String() != "10.0.0.0/8" || c.TrustedProxies[2].String() != "::1/128" {
		t.Fatalf("set: %v %v", c.TrustedProxies, err)
	}
	for _, bad := range []string{"127.0.0.1", "10.0.0.0/33", "proxy", "127.0.0.1/32,", "127.0.0.1/32,,10.0.0.0/8"} {
		t.Setenv("KEEP_TRUSTED_PROXIES", bad)
		if _, err := FromEnv(); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}
