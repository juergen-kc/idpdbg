//go:build windows

package main

import "golang.org/x/sys/windows"

// The PC/SC binding loads winscard.dll by bare name, which the default DLL
// search order would also look for in the current directory. Restrict the
// whole process to System32 before any card is touched (the DLL is loaded
// lazily, on the first PC/SC call, long after init).
func init() {
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		listReaders, connectCard = nil, nil // fail closed: card read reports PC/SC unavailable
	}
}
