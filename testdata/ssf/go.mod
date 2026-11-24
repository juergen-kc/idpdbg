// The transmitter the Shared Signals interop test runs against: SSFgo's
// conformance transmitter, an independent SSF 1.0 implementation. A module
// of its own, so it never becomes a dependency of idpdbg.
module idpdbg.test/ssf

go 1.27

require github.com/idfoundry/ssfgo v0.4.2
