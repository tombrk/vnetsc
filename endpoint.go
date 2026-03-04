package main

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// filteringEndpoint wraps a real tcpip.Endpoint. Denies all traffic.
type filteringEndpoint struct {
	tcpip.Endpoint
}

func (fe *filteringEndpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	vlog("DENY Connect → %v:%d", addr.Addr, addr.Port)
	return &tcpip.ErrConnectionRefused{}
}

func (fe *filteringEndpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	vlog("DENY Write")
	return 0, &tcpip.ErrConnectionRefused{}
}

func (fe *filteringEndpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrConnectionRefused{}
}

// httpEndpoint wraps a TCP endpoint. On Connect(), it redirects the
// guest to an internal loopback HTTP(S) proxy instead of the real
// upstream. The proxy detects TLS vs plaintext from the wire and
// reverse-proxies upstream through netstack. No Read/Write override needed.
type httpEndpoint struct {
	tcpip.Endpoint

	ns     *inet.Namespace
	family int
}

func (he *httpEndpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	vlog("HTTP Connect → %v:%d", addr.Addr, addr.Port)

	// Ensure the internal proxy is running.
	ensureProxy(he.ns)

	if internalProxy.listener == nil {
		vlog("HTTP Connect: proxy not available, denying")
		return &tcpip.ErrConnectionRefused{}
	}

	// Connect the guest's real endpoint to our internal loopback listener.
	err := he.Endpoint.Connect(internalProxy.addr)
	if err != nil {
		// ErrConnectStarted is normal for non-blocking connect.
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			vlog("HTTP Connect to proxy failed: %v", err)
			return err
		}
	}

	// Record guest's local port → original target mapping.
	localAddr, tcpErr := he.Endpoint.GetLocalAddress()
	if tcpErr != nil {
		vlog("HTTP Connect: GetLocalAddress: %v", tcpErr)
		return tcpErr
	}
	registerTarget(localAddr.Port, addr)

	return nil
}

func (he *httpEndpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

var _ tcpip.Endpoint = (*filteringEndpoint)(nil)
var _ tcpip.Endpoint = (*httpEndpoint)(nil)

var _ = fmt.Sprintf
