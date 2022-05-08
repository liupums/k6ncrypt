// https://github.com/salrashid123/signer/blob/master/example/sign_verify_pem/main.go
// https://github.com/golang/go/wiki/CodeReviewComments#receiver-type
package utils

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// wincrypt.h constants
	acquireCached           = 0x1                                             // CRYPT_ACQUIRE_CACHE_FLAG
	acquireSilent           = 0x40                                            // CRYPT_ACQUIRE_SILENT_FLAG
	acquireOnlyNCryptKey    = 0x40000                                         // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	encodingX509ASN         = 1                                               // X509_ASN_ENCODING
	encodingPKCS7           = 65536                                           // PKCS_7_ASN_ENCODING
	certStoreProvSystem     = 10                                              // CERT_STORE_PROV_SYSTEM
	certStoreCurrentUser    = uint32(certStoreCurrentUserID << compareShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	certStoreLocalMachine   = uint32(certStoreLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID  = 1                                               // CERT_SYSTEM_STORE_CURRENT_USER_ID
	certStoreLocalMachineID = 2                                               // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	infoIssuerFlag          = 4                                               // CERT_INFO_ISSUER_FLAG
	compareNameStrW         = 8                                               // CERT_COMPARE_NAME_STR_A
	compareShift            = 16                                              // CERT_COMPARE_SHIFT
	findIssuerStr           = compareNameStrW<<compareShift | infoIssuerFlag  // CERT_FIND_ISSUER_STR_W
	signatureKeyUsage       = 0x80                                            // CERT_DIGITAL_SIGNATURE_KEY_USAGE
	ncryptKeySpec           = 0xFFFFFFFF                                      // CERT_NCRYPT_KEY_SPEC

	// Legacy CryptoAPI flags
	bCryptPadPKCS1 uintptr = 0x2

	// winerror.h constants
	cryptENotFound = 0x80092004 // CRYPT_E_NOT_FOUND

	// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/bcrypt.h
	BCRYPT_SUPPORTED_PAD_PKCS1_ENC uintptr = 0x2
	BCRYPT_PAD_PSS                 uintptr = 0x8
)

// wide returns a pointer to a a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

var (
	// MY, CA and ROOT are well-known system stores that holds certificates.
	// The store that is opened (system or user) depends on the system call used.
	// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85).aspx)
	my                                = wide("MY")
	crypt32                           = windows.MustLoadDLL("crypt32.dll")
	nCrypt                            = windows.MustLoadDLL("ncrypt.dll")
	certDeleteCertificateFromStore    = crypt32.MustFindProc("CertDeleteCertificateFromStore")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	certFreeCertificateChain          = crypt32.MustFindProc("CertFreeCertificateChain")
	certGetCertificateChain           = crypt32.MustFindProc("CertGetCertificateChain")
	certGetIntendedKeyUsage           = crypt32.MustFindProc("CertGetIntendedKeyUsage")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	cryptFindCertificateKeyProvInfo   = crypt32.MustFindProc("CryptFindCertificateKeyProvInfo")
	nCryptSignHash                    = nCrypt.MustFindProc("NCryptSignHash")

	// algIDs maps crypto.Hash values to bcrypt.h constants.
	algIDs = map[crypto.Hash]*uint16{
		crypto.SHA1:   wide("SHA1"),   // BCRYPT_SHA1_ALGORITHM
		crypto.SHA256: wide("SHA256"), // BCRYPT_SHA256_ALGORITHM
		crypto.SHA384: wide("SHA384"), // BCRYPT_SHA384_ALGORITHM
		crypto.SHA512: wide("SHA512"), // BCRYPT_SHA512_ALGORITHM
	}
)

type WinCert struct {
	Issuer         string
	storeHandle    *windows.Handle
	x509cert       *x509.Certificate
	winCertContext *windows.CertContext
	privateKey     *uintptr
	refreshMutex   sync.Mutex
}

// certContextToX509 creates an x509.Certificate from a Windows cert context.
func CertContextToX509cert(ctx *windows.CertContext) (*x509.Certificate, error) {
	var der []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
	slice.Data = uintptr(unsafe.Pointer(ctx.EncodedCert))
	slice.Len = int(ctx.Length)
	slice.Cap = int(ctx.Length)
	return x509.ParseCertificate(der)
}

// CertContextPrivateKey wraps CryptAcquireCertificatePrivateKey. It obtains the CNG private
// key of a known certificate and returns a pointer to a Key which implements
// both crypto.Signer and crypto.Decrypter. When a nil cert context is passed
// a nil key is intentionally returned, to model the expected behavior of a
// non-existent cert having no private key.
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
func CertContextPrivateKey(cert *windows.CertContext) (*uintptr, error) {
	// Return early if a nil cert was passed.
	if cert == nil {
		return nil, nil
	}

	var (
		kh       uintptr
		spec     uint32
		mustFree int
	)

	r, _, err := cryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(cert)),
		acquireCached|acquireSilent|acquireOnlyNCryptKey,
		0, // Reserved, must be null.
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&spec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)

	// If the function succeeds, the return value is nonzero (TRUE).
	if r == 0 {
		return nil, fmt.Errorf("cryptAcquireCertificatePrivateKey returned %X: %v", r, err)
	}

	if mustFree != 0 {
		return nil, fmt.Errorf("wrong mustFree [%d != 0]", mustFree)
	}

	if spec != ncryptKeySpec {
		return nil, fmt.Errorf("wrong keySpec [%d != %d]", spec, ncryptKeySpec)
	}

	return &kh, nil
}

// findCert wraps the CertFindCertificateInStore call. Note that any cert context passed
// into prev will be freed. If no certificate was found, nil will be returned.
func findCert(store windows.Handle, encoding, findFlags, findType uint32, para *uint16, prev *windows.CertContext) (*windows.CertContext, error) {
	h, _, err := certFindCertificateInStore.Call(
		uintptr(store),
		uintptr(encoding),
		uintptr(findFlags),
		uintptr(findType),
		uintptr(unsafe.Pointer(para)),
		uintptr(unsafe.Pointer(prev)),
	)

	if h == 0 {
		// Actual error, or simply not found?
		if errno, ok := err.(syscall.Errno); ok && errno == cryptENotFound {
			return nil, nil
		}
		return nil, err
	}
	return (*windows.CertContext)(unsafe.Pointer(h)), nil
}

func NewWinCert(conf *WinCert) (WinCert, error) {
	if conf.Issuer == "" {
		return WinCert{}, fmt.Errorf("cert issuer cannot be empty")
	}

	// See https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
	// Open Localmachine\MY cert store
	store, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocalMachine,
		uintptr(unsafe.Pointer(my)))

	if err != nil {
		return WinCert{}, fmt.Errorf("CertOpenStore() failed for localmachine\\my store, returned: %v", err)
	}

	// pass 0 as the third parameter because it is not used
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376064(v=vs.85).aspx
	certCxt, err := findCert(
		store,
		encodingX509ASN|encodingPKCS7,
		0,
		findIssuerStr,
		wide(conf.Issuer),
		nil)

	if err != nil {
		windows.CertCloseStore(store, 1)
		return WinCert{}, fmt.Errorf("Failed to find certificate issued by %s: %v", conf.Issuer, err)
	}

	cert, err := CertContextToX509cert(certCxt)
	if err != nil {
		windows.CertCloseStore(store, 1)
		return WinCert{}, fmt.Errorf("Failed to convert cert context to x509 certificate : %v", err)
	}

	priv, err := CertContextPrivateKey(certCxt)
	if err != nil {
		windows.CertCloseStore(store, 1)
		return WinCert{}, fmt.Errorf("Failed to convert cert context to x509 certificate : %v", err)
	}

	conf.storeHandle = &store
	conf.x509cert = cert
	conf.winCertContext = certCxt
	conf.privateKey = priv
	return *conf, nil
}

func (w *WinCert) Public() crypto.PublicKey {
	return w.x509cert.PublicKey
}

func (w *WinCert) Close() error {
	if w.storeHandle != nil {
		return windows.CertCloseStore(*w.storeHandle, 1)
	}
	return nil
}

func (w *WinCert) TLSCertificate() tls.Certificate {
	var privKey crypto.PrivateKey = w
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        w.x509cert,
		Certificate: [][]byte{w.x509cert.Raw},
	}
}

// paddingInfo is the BCRYPT_PKCS1_PADDING_INFO struct in bcrypt.h.
type paddingInfo struct {
	pszAlgID *uint16
}

// paddingInfo is the  BCRYPT_PSS_PADDING_INFO struct in bcrypt.h.
type BCRYPT_PSS_PADDING_INFO struct {
	pszAlgID *uint16
	cbSalt   int
}

func SignPKCS1v15(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
	padInfo := paddingInfo{pszAlgID: algID}
	var size uint32
	// Obtain the size of the signature
	r, _, err := nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		BCRYPT_SUPPORTED_PAD_PKCS1_ENC)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during size check: %v", r, err)
	}

	// Obtain the signature data
	sig := make([]byte, size)
	r, _, err = nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		BCRYPT_SUPPORTED_PAD_PKCS1_ENC)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

func SignPSS(kh uintptr, digest []byte, hash crypto.Hash, pssOpts *rsa.PSSOptions) ([]byte, error) {
	// https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/crypto/rsa/pss.go;bpv=1;bpt=1
	if pssOpts.SaltLength != -1 {
		return nil, fmt.Errorf("Only support PSSSaltLengthEqualsHash for now")
	}

	padInfo := BCRYPT_PSS_PADDING_INFO{
		pszAlgID: algIDs[hash],
		cbSalt:   hash.Size(), // PSSSaltLengthEqualsHash
	}

	var size uint32
	// Obtain the size of the signature
	r, _, err := nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		BCRYPT_PAD_PSS)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during size check: %v", r, err)
	}

	// Obtain the signature data
	sig := make([]byte, size)
	r, _, err = nCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		BCRYPT_PAD_PSS)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

// Core function to implement crypto.Signer
func (t *WinCert) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	fmt.Printf("WinCert::Sign is called\n")

	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	hf := opts.HashFunc()
	algID, ok := algIDs[hf]
	if !ok {
		return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
	}

	var sig []byte
	var err error
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		fmt.Printf("WinCert::SignPSS is called\n")
		sig, err = SignPSS(*t.privateKey, digest, hf, pssOpts)
		if err != nil {
			fmt.Printf("failed to sign RSA-SignPSS %v", err)
		}
	} else {
		fmt.Printf("WinCert::SignPKCS1v15 is called\n")
		sig, err = SignPKCS1v15(*t.privateKey, digest, algID)
		if err != nil {
			fmt.Printf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
	}

	fmt.Printf("--result by WinCert private key\n")
	fmt.Printf("sig %s\n", hex.EncodeToString(sig))
	fmt.Printf("-----\n")

	return sig, nil
}
