package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"golang.org/x/sys/unix"
)

const secretAnnotationPrefix = "vnetsc.test/secrets/"

// Secret describes a secret to inject into HTTP requests.
type Secret struct {
	Name string // e.g. "anthropic"
	URL  string // e.g. "https://api.anthropic.com"
	Env  string // env var name, e.g. "ANTHROPIC_API_KEY"
	Fake string // placeholder value set in the container env
	Real string // real secret value
	Type string // e.g. "bearer"
}

// secrets is populated during init() from OCI annotations.
var secrets []Secret

func init() {
	if !isBoot() {
		return
	}

	specFD := findSpecFD()
	if specFD < 0 {
		return
	}

	parsed, err := parseSecretsFromSpecFD(specFD)
	if err != nil {
		vlog("secrets: parse spec FD %d: %v", specFD, err)
		return
	}
	secrets = parsed
	for _, s := range secrets {
		vlog("secrets: loaded %s url=%s env=%s type=%s", s.Name, s.URL, s.Env, s.Type)
	}
}

// isLastBootStage returns true when --setup-root=false and --apply-caps=false,
// meaning this is the final boot invocation that will actually run the sentry.
func isLastBootStage() bool {
	for _, arg := range os.Args {
		if arg == "--setup-root" {
			return false // first stage
		}
	}
	return true
}

// findSpecFD parses --spec-fd=N or --spec-fd N from os.Args.
func findSpecFD() int {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--spec-fd=") {
			val := strings.TrimPrefix(arg, "--spec-fd=")
			fd, err := strconv.Atoi(val)
			if err != nil {
				return -1
			}
			return fd
		}
		if arg == "--spec-fd" && i+1 < len(os.Args) {
			fd, err := strconv.Atoi(os.Args[i+1])
			if err != nil {
				return -1
			}
			return fd
		}
	}
	return -1
}

// parseSecretsFromSpecFD reads the OCI spec from the given FD, extracts
// secret annotations, and seeks the FD back to 0 so the boot command
// can still read it.
func parseSecretsFromSpecFD(fd int) ([]Secret, error) {
	f := os.NewFile(uintptr(fd), "spec-fd")
	if f == nil {
		return nil, fmt.Errorf("invalid fd %d", fd)
	}
	// Do NOT close f — the boot command needs it.

	// Try to seek to start first (the FD may have been read by a prior boot
	// stage and inherited with position at EOF). If seek fails, it's a pipe.
	seekable := true
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		seekable = false
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	vlog("secrets: read %d bytes from spec FD %d (seekable=%v)", len(data), fd, seekable)

	if seekable {
		// Seek back so boot can re-read.
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek-back: %w", err)
		}
	} else {
		// Non-seekable (pipe). Replace with a seekable memfd.
		f.Close()
		memfd, err := unix.MemfdCreate("spec", 0)
		if err != nil {
			return nil, fmt.Errorf("memfd_create: %w", err)
		}
		if _, err := unix.Write(memfd, data); err != nil {
			unix.Close(memfd)
			return nil, fmt.Errorf("write memfd: %w", err)
		}
		if _, err := unix.Seek(memfd, 0, io.SeekStart); err != nil {
			unix.Close(memfd)
			return nil, fmt.Errorf("seek memfd: %w", err)
		}
		if memfd != fd {
			if err := unix.Dup2(memfd, fd); err != nil {
				unix.Close(memfd)
				return nil, fmt.Errorf("dup2(%d→%d): %w", memfd, fd, err)
			}
			unix.Close(memfd)
		}
	}

	// We only need the annotations field.
	var spec struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	var result []Secret
	for key, val := range spec.Annotations {
		if !strings.HasPrefix(key, secretAnnotationPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, secretAnnotationPrefix)
		s, err := parseSecretAnnotation(name, val)
		if err != nil {
			vlog("secrets: bad annotation %s: %v", key, err)
			continue
		}
		result = append(result, s)
	}
	return result, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// parseSecretAnnotation parses a value like:
//
//	url=https://api.anthropic.com env=ANTHROPIC_API_KEY value=sk-xxx type=bearer
func parseSecretAnnotation(name, raw string) (Secret, error) {
	s := Secret{Name: name}
	fields := strings.Fields(raw)
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return s, fmt.Errorf("bad field %q", f)
		}
		switch k {
		case "url":
			s.URL = v
		case "env":
			s.Env = v
		case "value":
			s.Real = v
		case "type":
			s.Type = v
		default:
			return s, fmt.Errorf("unknown field %q", k)
		}
	}
	if s.URL == "" || s.Env == "" || s.Real == "" {
		return s, fmt.Errorf("url, env, and value are required")
	}
	if s.Type == "" {
		s.Type = "bearer"
	}
	// Generate a deterministic fake value.
	s.Fake = "vnetsc-placeholder-" + s.Name
	return s, nil
}

// findSecretForHost returns the secret matching the given host (from URL), or nil.
func findSecretForHost(host string) *Secret {
	for i := range secrets {
		s := &secrets[i]
		// Extract host from the secret's URL.
		u := s.URL
		u = strings.TrimPrefix(u, "https://")
		u = strings.TrimPrefix(u, "http://")
		u = strings.TrimSuffix(u, "/")
		// Compare with host (which may include port).
		h := strings.Split(host, ":")[0]
		if h == u || strings.Split(u, "/")[0] == h {
			return s
		}
	}
	return nil
}
