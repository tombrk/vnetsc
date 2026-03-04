package main

import (
	"context"
	"crypto/tls"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	_ "github.com/breml/rootcerts" // embed Mozilla root CAs for upstream TLS verification



	"gvisor.dev/gvisor/pkg/sentry/inet"
	netstackimpl "gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// internalProxy is the singleton in-process HTTP(S) reverse proxy that
// listens on a loopback port inside netstack. Guest TCP connections are
// redirected here instead of going to the real upstream.
var internalProxy struct {
	once     sync.Once
	listener *gonet.TCPListener
	addr     tcpip.FullAddress // 127.0.0.1:<port>
	nstack   *stack.Stack

	// targets maps accepted-conn remote port → original target address.
	targets sync.Map // uint16 → tcpip.FullAddress
}

// ensureProxy starts the internal listener + http.Server once.
func ensureProxy(ns *inet.Namespace) {
	internalProxy.once.Do(func() {
		nstack := ns.Stack().(*netstackimpl.Stack).Stack
		internalProxy.nstack = nstack

		addr := tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: 0, // ephemeral
		}
		ln, err := gonet.ListenTCP(nstack, addr, ipv4.ProtocolNumber)
		if err != nil {
			vlog("proxy: listen failed: %v", err)
			return
		}
		internalProxy.listener = ln

		// Get the assigned port.
		tcpAddr := ln.Addr().(*net.TCPAddr)
		internalProxy.addr = tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: uint16(tcpAddr.Port),
		}
		vlog("proxy: listening on 127.0.0.1:%d", tcpAddr.Port)

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				// Determine upstream scheme from the TLS state.
				if req.TLS != nil {
					req.URL.Scheme = "https"
				} else {
					req.URL.Scheme = "http"
				}
				if req.URL.Host == "" {
					req.URL.Host = req.Host
				}
			},
			Transport: &proxyTransport{},
		}

		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vlog("HTTP %s %s%s", r.Method, r.Host, r.URL)
				injectSecret(r)
				proxy.ServeHTTP(w, r)
			}),
			TLSConfig: &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					vlog("TLS SNI: %s", hello.ServerName)
					return mitmCertForHost(hello.ServerName)
				},
			},
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				// Stash the connection so the handler can find the target.
				return context.WithValue(ctx, connKey{}, c)
			},
			ErrorLog: stdlog.New(logWriter{}, "http.Server: ", 0),
		}

		go func() {
			// Serve with TLS detection: the listener Accept()s raw TCP
			// connections. We wrap each with a tls.Server or pass through
			// based on the first byte (0x16 = TLS).
			for {
				conn, err := ln.Accept()
				if err != nil {
					vlog("proxy: accept error: %v", err)
					return
				}
				go handleConn(srv, conn)
			}
		}()
	})
}

// handleConn peeks the first byte to detect TLS, then serves HTTP.
func handleConn(srv *http.Server, conn net.Conn) {
	first := make([]byte, 1)
	if _, err := conn.Read(first); err != nil {
		vlog("proxy: peek error: %v", err)
		conn.Close()
		return
	}
	pc := &prefixConn{prefix: first, Conn: conn}

	// We need ConnContext to pass the underlying TCP conn to the handler,
	// so we create a per-connection server (lightweight).
	perConn := &http.Server{
		Handler: srv.Handler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Always stash the original TCP conn (pc), not the TLS wrapper.
			return context.WithValue(ctx, connKey{}, pc.Conn)
		},
		ErrorLog: srv.ErrorLog,
	}

	if first[0] == 0x16 {
		// TLS — terminate with our MITM cert, serve HTTP on top.
		tlsConn := tls.Server(pc, srv.TLSConfig)
		_ = perConn.Serve(singleListener(tlsConn))
	} else {
		// Plaintext HTTP
		_ = perConn.Serve(singleListener(pc))
	}
}

type connKey struct{}

// proxyTransport dials upstream through netstack, using real TLS for HTTPS.
type proxyTransport struct{}

func (t *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Find the original target from the connection's remote port.
	conn, _ := req.Context().Value(connKey{}).(net.Conn)
	if conn == nil {
		return nil, fmt.Errorf("no connection in context")
	}

	remotePort := uint16(0)
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remotePort = uint16(tcpAddr.Port)
	}
	targetVal, ok := internalProxy.targets.Load(remotePort)
	if !ok {
		return nil, fmt.Errorf("no target for remote port %d", remotePort)
	}
	target := targetVal.(tcpip.FullAddress)

	// Dial upstream through netstack.
	vlog("proxy: dialing upstream %v:%d", target.Addr, target.Port)
	upstream, err := gonet.DialTCP(internalProxy.nstack, target, ipv4.ProtocolNumber)
	if err != nil {
		vlog("proxy: dial upstream failed: %v", err)
		return nil, fmt.Errorf("dial upstream %v:%d: %v", target.Addr, target.Port, err)
	}
	vlog("proxy: upstream connected")

	var transport http.RoundTripper
	transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return upstream, nil
		},
		// rootcerts package embeds Mozilla CAs, so TLS verification works
		// without filesystem access (no seccomp violation).
	}

	// Rewrite to relative URL.
	req.RequestURI = ""
	resp, err := transport.RoundTrip(req)
	if err != nil {
		vlog("proxy: upstream RoundTrip error: %v", err)
	}
	return resp, err
}

// registerTarget records the mapping from guest local port → original target.
func registerTarget(localPort uint16, target tcpip.FullAddress) {
	internalProxy.targets.Store(localPort, target)
	vlog("proxy: registered port %d → %v:%d", localPort, target.Addr, target.Port)
}

// prefixConn prepends already-read bytes before the underlying conn.
type prefixConn struct {
	prefix []byte
	net.Conn
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// singleListener yields one conn then blocks.
func singleListener(c net.Conn) net.Listener {
	return &oneShotListener{conn: c, done: make(chan struct{})}
}

type oneShotListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return pipeAddr{} }

type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	vlog("%s", string(p))
	return len(p), nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// injectSecret replaces credentials in outbound HTTP requests based on
// configured secrets. For type=bearer, it swaps the placeholder token.
// For type=git, it unconditionally injects Basic auth with the PAT.
func injectSecret(r *http.Request) {
	// Try bearer first.
	if s := findSecretForHost(r.Host); s != nil {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+s.Fake {
			r.Header.Set("Authorization", "Bearer "+s.Real)
			vlog("secret: injected bearer %s for %s", s.Name, r.Host)
			return
		}
	}

	// Try git.
	if s := findGitSecret(r.Host, r.URL.Path); s != nil {
		r.Header.Set("Authorization", gitBasicAuth(s))
		vlog("secret: injected git %s for %s%s", s.Name, r.Host, r.URL.Path)
	}
}
