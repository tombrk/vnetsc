package main

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// filteringProvider wraps the original socket providers for a given address
// family. It delegates socket creation to the originals, then swaps the
// tcpip.Endpoint inside the returned sock with a filtering wrapper.
type filteringProvider struct {
	orig []socket.Provider
}

func (fp *filteringProvider) Socket(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *syserr.Error) {
	// Inject MITM CA into guest trust store on first socket call.
	injectMITMCert(t)

	for _, p := range fp.orig {
		fd, err := p.Socket(t, stype, protocol)
		if err != nil {
			return nil, err
		}
		if fd == nil {
			continue
		}

		sm := getSockMirror(fd)

		// For TCP sockets, use httpEndpoint so we can intercept port-80 flows.
		// The actual port decision happens at Connect() time.
		if stype == linux.SOCK_STREAM {
			if _, ok := sm.Endpoint.(*tcp.Endpoint); ok {
				vlog("Socket(family=%d, type=STREAM, proto=%d) → httpEndpoint", sm.family, sm.protocol)
				sm.Endpoint = &httpEndpoint{Endpoint: sm.Endpoint, ns: sm.namespace, family: sm.family}
				return fd, nil
			}
		}

		// Everything else: basic filtering (DNS allowed, rest denied at connect).
		vlog("Socket(family=%d, type=%d, proto=%d) → filteringEndpoint", sm.family, sm.skType, sm.protocol)
		sm.Endpoint = &filteringEndpoint{Endpoint: sm.Endpoint}
		return fd, nil
	}
	return nil, nil
}

func (fp *filteringProvider) Pair(t *kernel.Task, stype linux.SockType, protocol int) (*vfs.FileDescription, *vfs.FileDescription, *syserr.Error) {
	for _, p := range fp.orig {
		s1, s2, err := p.Pair(t, stype, protocol)
		if err != nil {
			return nil, nil, err
		}
		if s1 != nil {
			return s1, s2, nil
		}
	}
	return nil, nil, nil
}
