package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// mitmCA holds the generated CA certificate and key.
var mitmCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	ready   bool
}

var mitmCertCache sync.Map // host → *tls.Certificate
var mitmInjectOnce sync.Once

// generateMITMCA creates the CA key pair and cert. Called once.
func generateMITMCA() {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		vlog("MITM: generate CA key: %v", err)
		return
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"vnetsc MITM CA"},
			CommonName:   "vnetsc MITM CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		vlog("MITM: create CA cert: %v", err)
		return
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		vlog("MITM: parse CA cert: %v", err)
		return
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	mitmCA.cert = caCert
	mitmCA.key = caKey
	mitmCA.certPEM = caPEM
	mitmCA.ready = true

	vlog("MITM: CA generated")
}

// injectMITMCert writes the CA cert into the guest filesystem's trust store.
// Called once from the first Socket() call, using the task's VFS context.
func injectMITMCert(t *kernel.Task) {
	mitmInjectOnce.Do(func() {
		generateMITMCA()
		if !mitmCA.ready {
			return
		}
		injectCACertVFS(t)
	})
}

// injectCACertVFS appends the CA cert to common trust store paths in the guest VFS.
func injectCACertVFS(t *kernel.Task) {
	ctx := t.AsyncContext()
	creds := auth.NewRootCredentials(t.Credentials().UserNamespace)
	vfsObj := t.Kernel().VFS()
	mns := t.MountNamespace()
	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	caBundlePaths := []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
		"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
		"/etc/ssl/ca-bundle.pem",              // openSUSE
	}

	payload := append([]byte("\n# vnetsc MITM CA\n"), mitmCA.certPEM...)

	for _, p := range caBundlePaths {
		if err := appendToGuestFile(ctx, vfsObj, creds, root, p, payload); err != nil {
			vlog("MITM: append to %s: %v", p, err)
		} else {
			vlog("MITM: injected CA into %s", p)
		}
	}
}

// appendToGuestFile opens a file in the guest VFS and appends data.
func appendToGuestFile(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path string, data []byte) error {
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(path),
		FollowFinalSymlink: true,
	}

	fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_APPEND,
	})
	if err != nil {
		return err
	}
	defer fd.DecRef(ctx)

	src := usermem.BytesIOSequence(data)
	n, err := fd.Write(ctx, src, vfs.WriteOptions{})
	if err != nil {
		return err
	}
	vlog("MITM: wrote %d bytes to %s", n, path)
	return nil
}

// mitmCertForHost generates (or returns cached) a TLS certificate for the
// given host, signed by our CA.
func mitmCertForHost(host string) (*tls.Certificate, error) {
	if !mitmCA.ready {
		return nil, fmt.Errorf("MITM CA not initialized")
	}

	if cached, ok := mitmCertCache.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, mitmCA.cert, &leafKey.PublicKey, mitmCA.key)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafDER, mitmCA.cert.Raw},
		PrivateKey:  leafKey,
	}

	mitmCertCache.Store(host, tlsCert)
	return tlsCert, nil
}
