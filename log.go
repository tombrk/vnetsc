package main

import (
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/pkg/log"
)

var vlogPrefix string

func init() {
	args := "?"
	if len(os.Args) > 1 {
		args = os.Args[1]
	}
	vlogPrefix = "vnetsc[" + filepath.Base(os.Args[0]) + "/" + args + "]: "
}

func vlog(format string, args ...any) {
	log.Warningf(vlogPrefix+format, args...)
}
