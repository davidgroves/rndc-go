// Command rndc-go is a CLI for ISC BIND's RNDC protocol.
package main

import (
	"os"
	"runtime/debug"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

func programVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	if version == "" {
		return "dev"
	}
	return version
}
