//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows WebAuthn API (webauthn.dll, Windows 10 1903 and later),
// called without cgo. The structures mirror webauthn.h; idpdbg passes the
// version 1 option structures, which every version of the API accepts.

var (
	modWebAuthn                   = windows.NewLazySystemDLL("webauthn.dll")
	procGetAPIVersion             = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procMakeCredential            = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procGetAssertion              = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeCredentialAttestation = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procFreeAssertion             = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procGetErrorName              = modWebAuthn.NewProc("WebAuthNGetErrorName")
	modUser32                     = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow       = modUser32.NewProc("GetForegroundWindow")
	modKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow          = modKernel32.NewProc("GetConsoleWindow")
)

const (
	wanAttachmentCrossPlatform = 2
	wanAttestationDirect       = 3
	wanUVRequired              = 1
	wanUVPreferred             = 2
	wanUVDiscouraged           = 3
)

type wanRPEntity struct {
	Version uint32
	ID      *uint16
	Name    *uint16
	Icon    *uint16
}

type wanUserEntity struct {
	Version     uint32
	IDLen       uint32
	ID          *byte
	Name        *uint16
	Icon        *uint16
	DisplayName *uint16
}

type wanCoseParam struct {
	Version uint32
	Type    *uint16
	Alg     int32
}

type wanCoseParams struct {
	Count  uint32
	Params *wanCoseParam
}

type wanClientData struct {
	Version uint32
	JSONLen uint32
	JSON    *byte
	HashAlg *uint16
}

type wanCredential struct {
	Version uint32
	IDLen   uint32
	ID      *byte
	Type    *uint16
}

type wanCredentials struct {
	Count uint32
	Creds *wanCredential
}

type wanExtensions struct {
	Count uint32
	Exts  uintptr
}

type wanMakeCredentialOptions struct {
	Version             uint32
	TimeoutMilliseconds uint32
	CredentialList      wanCredentials
	Extensions          wanExtensions
	Attachment          uint32
	RequireResidentKey  int32
	UserVerification    uint32
	Attestation         uint32
	Flags               uint32
}

type wanGetAssertionOptions struct {
	Version             uint32
	TimeoutMilliseconds uint32
	CredentialList      wanCredentials
	Extensions          wanExtensions
	Attachment          uint32
	UserVerification    uint32
	Flags               uint32
}

type wanCredentialAttestation struct {
	Version            uint32
	FormatType         *uint16
	AuthDataLen        uint32
	AuthData           *byte
	AttestationLen     uint32
	Attestation        *byte
	AttestationDecode  uint32
	AttestationDecoded uintptr
	AttObjectLen       uint32
	AttObject          *byte
	CredIDLen          uint32
	CredID             *byte
	// version 2
	Extensions wanExtensions
	// version 3
	UsedTransport uint32
}

type wanAssertion struct {
	Version     uint32
	AuthDataLen uint32
	AuthData    *byte
	SigLen      uint32
	Sig         *byte
	Credential  wanCredential
	UserIDLen   uint32
	UserID      *byte
}

type windowsWebAuthn struct{ version uint32 }

func init() {
	if modWebAuthn.Load() != nil || procGetAPIVersion.Find() != nil {
		return // Windows before 10 1903: no API, so security keys need administrator rights
	}
	v, _, _ := procGetAPIVersion.Call()
	platformAPI = &windowsWebAuthn{version: uint32(v)}
}

func (w *windowsWebAuthn) Name() string {
	return fmt.Sprintf("the Windows WebAuthn API (version %d)", w.version)
}

func wstr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func bytesPtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

func goBytes(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte{}, unsafe.Slice(p, n)...)
}

// window is the window the system dialog belongs to: the foreground one,
// else the console's.
func window() uintptr {
	if h, _, _ := procGetForegroundWindow.Call(); h != 0 {
		return h
	}
	h, _, _ := procGetConsoleWindow.Call()
	return h
}

func wanError(hr uintptr) error {
	name := ""
	if p, _, _ := procGetErrorName.Call(hr); p != 0 {
		// A static string inside webauthn.dll, never freed or moved.
		name = windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p)))
	}
	switch name {
	case "NotAllowedError":
		return fmt.Errorf("%s (0x%08X): the person cancelled, nobody touched the key in time, or no key holds a matching credential", name, uint32(hr))
	case "InvalidStateError":
		return fmt.Errorf("%s (0x%08X): the key already holds a credential from the exclude list (registered before)", name, uint32(hr))
	case "":
		return fmt.Errorf("Windows WebAuthn API error 0x%08X", uint32(hr))
	}
	return fmt.Errorf("%s (0x%08X)", name, uint32(hr))
}

func wanUV(p string) uint32 {
	switch p {
	case "required":
		return wanUVRequired
	case "discouraged":
		return wanUVDiscouraged
	}
	return wanUVPreferred
}

func wanCredList(ids [][]byte, typ *uint16) wanCredentials {
	if len(ids) == 0 {
		return wanCredentials{}
	}
	list := make([]wanCredential, len(ids))
	for i, id := range ids {
		list[i] = wanCredential{Version: 1, IDLen: uint32(len(id)), ID: bytesPtr(id), Type: typ}
	}
	return wanCredentials{Count: uint32(len(list)), Creds: &list[0]}
}

func (w *windowsWebAuthn) MakeCredential(r platformCreate) (*platformAttestation, error) {
	typ := wstr("public-key")
	rp := &wanRPEntity{Version: 1, ID: wstr(r.RPID), Name: wstr(r.RPName)}
	user := &wanUserEntity{Version: 1, IDLen: uint32(len(r.UserID)), ID: bytesPtr(r.UserID), Name: wstr(r.UserName), DisplayName: wstr(r.UserDisplayName)}
	if len(r.Algs) == 0 {
		return nil, errors.New("no algorithms")
	}
	params := make([]wanCoseParam, len(r.Algs))
	for i, a := range r.Algs {
		params[i] = wanCoseParam{Version: 1, Type: typ, Alg: int32(a)}
	}
	cp := &wanCoseParams{Count: uint32(len(params)), Params: &params[0]}
	cd := &wanClientData{Version: 1, JSONLen: uint32(len(r.ClientDataJSON)), JSON: bytesPtr(r.ClientDataJSON), HashAlg: wstr("SHA-256")}
	rk := int32(0)
	if r.ResidentKey {
		rk = 1
	}
	opts := &wanMakeCredentialOptions{Version: 1, TimeoutMilliseconds: uint32(r.Timeout.Milliseconds()), CredentialList: wanCredList(r.Exclude, typ),
		Attachment: wanAttachmentCrossPlatform, RequireResidentKey: rk, UserVerification: wanUV(r.UserVerification), Attestation: wanAttestationDirect}
	var res *wanCredentialAttestation
	hr, _, _ := procMakeCredential.Call(window(), uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(cp)),
		uintptr(unsafe.Pointer(cd)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&res)))
	runtime.KeepAlive(params)
	runtime.KeepAlive(r)
	if hr != 0 {
		return nil, wanError(hr)
	}
	if res == nil {
		return nil, errors.New("the Windows WebAuthn API returned no credential")
	}
	defer procFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(res)))
	out := &platformAttestation{Format: windows.UTF16PtrToString(res.FormatType), AuthData: goBytes(res.AuthData, res.AuthDataLen),
		AttStmtRaw: goBytes(res.Attestation, res.AttestationLen)}
	if res.Version >= 3 {
		out.Transport = map[uint32]string{1: "usb", 2: "nfc", 4: "ble", 8: "test", 0x10: "internal", 0x20: "hybrid"}[res.UsedTransport]
	}
	return out, nil
}

func (w *windowsWebAuthn) GetAssertion(r platformGet) (*platformAssertion, error) {
	typ := wstr("public-key")
	cd := &wanClientData{Version: 1, JSONLen: uint32(len(r.ClientDataJSON)), JSON: bytesPtr(r.ClientDataJSON), HashAlg: wstr("SHA-256")}
	opts := &wanGetAssertionOptions{Version: 1, TimeoutMilliseconds: uint32(r.Timeout.Milliseconds()), CredentialList: wanCredList(r.Allow, typ),
		Attachment: wanAttachmentCrossPlatform, UserVerification: wanUV(r.UserVerification)}
	var res *wanAssertion
	hr, _, _ := procGetAssertion.Call(window(), uintptr(unsafe.Pointer(wstr(r.RPID))), uintptr(unsafe.Pointer(cd)), uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&res)))
	runtime.KeepAlive(r)
	if hr != 0 {
		return nil, wanError(hr)
	}
	if res == nil {
		return nil, errors.New("the Windows WebAuthn API returned no assertion")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(res)))
	return &platformAssertion{CredID: goBytes(res.Credential.ID, res.Credential.IDLen), AuthData: goBytes(res.AuthData, res.AuthDataLen),
		Signature: goBytes(res.Sig, res.SigLen), UserHandle: goBytes(res.UserID, res.UserIDLen)}, nil
}
