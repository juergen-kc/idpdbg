//go:build !linux && !(darwin && cgo)

package main

import "runtime"

func init() {
	switch runtime.GOOS {
	case "darwin":
		hidUnavailable = "this build has no USB security key support (macOS needs a cgo build for IOKit)"
	case "windows":
		hidUnavailable = "Windows lets only administrators talk to FIDO security keys directly; other programs must go through the Windows WebAuthn API, which idpdbg does not use"
	}
}
