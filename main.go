// Binary vnetsc is a gVisor runtime (runsc) with network filtering injected.
package main

import (
	"os"
	_ "unsafe" // required for go:linkname

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/runsc/cli/maincli"
	"gvisor.dev/gvisor/runsc/version"

	// Blank-import netstack to ensure its init() registers the real providers
	// before ours runs.
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netstack"
)

// Access the unexported families map from pkg/sentry/socket.
//
//go:linkname socketFamilies gvisor.dev/gvisor/pkg/sentry/socket.families
var socketFamilies map[int][]socket.Provider

var _ = version.Version()

func isBoot() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--" {
			return false
		}
		if arg == "boot" {
			return true
		}
	}
	return false
}

func init() {
	if !isBoot() {
		return
	}

	// By the time this init() runs, netstack's init() has already
	// registered providers for AF_INET, AF_INET6, AF_PACKET.
	// We wrap AF_INET and AF_INET6 with our filtering provider.
	for _, family := range []int{linux.AF_INET, linux.AF_INET6} {
		orig := socketFamilies[family]
		if len(orig) == 0 {
			continue
		}
		vlog("wrapping %d provider(s) for family %d", len(orig), family)
		socketFamilies[family] = []socket.Provider{
			&filteringProvider{orig: orig},
		}
	}
}

func main() {
	maincli.Main()
}
