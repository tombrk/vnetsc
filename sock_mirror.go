package main

import (
	"sync"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// sockMirror is a layout-identical copy of netstack.sock.
// Every field type is exported; only the original struct name is unexported.
// We use this to unsafe-cast through the vfs.FileDescription.Impl() interface
// and reach the Endpoint field.
//
// KEEP IN SYNC with pkg/sentry/socket/netstack/netstack.go type sock struct.
type sockMirror struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD
	socket.SendReceiveTimeout
	*waiter.Queue

	family   int
	Endpoint tcpip.Endpoint
	skType   linux.SockType
	protocol int

	namespace *inet.Namespace

	mu         sync.Mutex
	readWriter usermem.IOSequenceReadWriter

	readMu           sync.Mutex
	sockOptTimestamp  bool
	timestampValid   bool
	timestamp        time.Time

	sockOptInq bool
}

// getSockMirror extracts the *sockMirror from a *vfs.FileDescription.
// fd.Impl() returns the socket.Socket interface value, which holds a pointer
// to the netstack.sock. We reinterpret that pointer as our mirror struct.
func getSockMirror(fd *vfs.FileDescription) *sockMirror {
	impl := fd.Impl()
	// An interface is (type_ptr, data_ptr). We want data_ptr.
	iface := (*[2]unsafe.Pointer)(unsafe.Pointer(&impl))
	return (*sockMirror)(iface[1])
}
