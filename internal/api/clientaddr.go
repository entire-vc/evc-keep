package api

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientAddr is the address a pre-authentication budget is kept for: the
// immediate peer, an IPv4 address as is and an IPv6 one as its /64, since one
// host is commonly handed a whole /64. A peer inside trusted (a reverse proxy
// in front of Keep) is replaced by the rightmost X-Forwarded-For address that
// is not itself trusted; several X-Forwarded-For headers are read in order as
// one list. The walk stops at the first element that does not parse and keeps
// the peer: stepping over it would let a client name any address it likes. A
// peer outside trusted is used as is, whatever it sends.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := peerAddr(r.RemoteAddr)
	if !peer.IsValid() || !inPrefixes(peer, trusted) {
		return addrBucket(peer)
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addrBucket(peer)
		}
		client = a.Unmap()
		if !inPrefixes(client, trusted) {
			break
		}
	}
	return addrBucket(client)
}

// peerAddr parses RemoteAddr, host:port or a bare address; anything else is
// the zero Addr, which all such requests share.
func peerAddr(remote string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(remote); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func addrBucket(a netip.Addr) netip.Addr {
	if a.Is6() {
		p, _ := a.WithZone("").Prefix(64)
		return p.Addr()
	}
	return a
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// addrKey is the limiter key of a client address.
func addrKey(a netip.Addr) bucketKey {
	return bucketKey{id: a.As16()}
}
