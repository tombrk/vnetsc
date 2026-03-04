package main

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// filteringEndpoint wraps a real tcpip.Endpoint. Only DNS (port 53) is allowed.
type filteringEndpoint struct {
	tcpip.Endpoint
}

func (fe *filteringEndpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	if addr.Port != 53 {
		vlog("DENY Connect → %v:%d", addr.Addr, addr.Port)
		return &tcpip.ErrConnectionRefused{}
	}
	vlog("Connect → %v:%d", addr.Addr, addr.Port)
	return fe.Endpoint.Connect(addr)
}

func (fe *filteringEndpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	if opts.To != nil && opts.To.Port != 53 {
		vlog("DENY Write to=%v:%d", opts.To.Addr, opts.To.Port)
		return 0, &tcpip.ErrConnectionRefused{}
	}
	return fe.Endpoint.Write(p, opts)
}

func (fe *filteringEndpoint) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	return fe.Endpoint.Read(w, opts)
}

func (fe *filteringEndpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	ep, wq, err := fe.Endpoint.Accept(peerAddr)
	if err != nil {
		return nil, nil, err
	}
	return &filteringEndpoint{Endpoint: ep}, wq, nil
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
