package builtin

import "testing"

// The https fetch dials only public addresses: everything an operator could
// point mesh_url at inside the network must be refused.
func TestPublicDialAddress(t *testing.T) {
	refused := []string{
		"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "172.16.0.1:443", "172.31.255.255:443", "192.168.1.1:443",
		"169.254.169.254:80", "[fe80::1]:443", "[fc00::1]:443", "[fd12:3456::1]:443", "100.64.0.1:443", "100.127.255.255:443",
		"0.0.0.0:443", "[::]:443", "224.0.0.1:443", "[::ffff:10.0.0.1]:443", "[::ffff:127.0.0.1]:443", "[::ffff:100.64.0.1]:443",
		"example.com:443", "10.0.0.1", "",
		"[64:ff9b::a00:1]:443", "[64:ff9b::7f00:1]:443", "[2002:a00:1::1]:443", "[2002:7f00:1::1]:443",
		"[2001:0:4136:e378:8000:63bf:3fff:fdd2]:443", "198.18.0.1:443", "192.0.0.1:443", "192.0.2.1:443",
		"198.51.100.1:443", "203.0.113.1:443", "240.0.0.1:443", "[::127.0.0.1]:443", "[2001:db8::1]:443",
	}
	for _, a := range refused {
		if publicDialAddress(a) {
			t.Errorf("%q was accepted as public", a)
		}
	}
	for _, a := range []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443", "172.32.0.1:443", "100.128.0.1:443", "100.63.255.255:443"} {
		if !publicDialAddress(a) {
			t.Errorf("%q was refused, but it is public", a)
		}
	}
}

// Plain http (local development) dials loopback only: a name that resolves
// anywhere else must not receive the token in cleartext.
func TestLoopbackDialAddress(t *testing.T) {
	for _, a := range []string{"127.0.0.1:80", "[::1]:80", "[::ffff:127.0.0.1]:80", "127.9.9.9:80"} {
		if !loopbackDialAddress(a) {
			t.Errorf("%q was refused, but it is loopback", a)
		}
	}
	for _, a := range []string{"10.0.0.1:80", "8.8.8.8:80", "169.254.169.254:80", "0.0.0.0:80", "[::]:80", "evil.localhost:80", "127.0.0.1", ""} {
		if loopbackDialAddress(a) {
			t.Errorf("%q was accepted as loopback", a)
		}
	}
}
