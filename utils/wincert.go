/*
   WinCert is an util class to wrap a windows cert object in Localmachine\My cert store
   It has a CNG private key and implements crypto.Signer
*/
// https://github.com/salrashid123/signer/blob/master/example/sign_verify_pem/main.go
// https://github.com/golang/go/wiki/CodeReviewComments#receiver-type
package utils

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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
	certStoreLocalMachine   = uint32(certStoreLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreLocalMachineID = 2                                               // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	compareSha1Hash         = 1                                               // CERT_COMPARE_SHA1_HASH
	compareShift            = 16                                              // CERT_COMPARE_SHIFT
	findSha1Hash            = compareSha1Hash << compareShift                 // CERT_FIND_SHA1_HASH
	signatureKeyUsage       = 0x80                                            // CERT_DIGITAL_SIGNATURE_KEY_USAGE
	ncryptKeySpec           = 0xFFFFFFFF                                      // CERT_NCRYPT_KEY_SPEC
	embeddedCaOid           = "1.2.840.113556.1.8000.2554.197254.100"         // Embedded CA OID

	// Legacy CryptoAPI flags
	bCryptPadPKCS1 uintptr = 0x2

	// winerror.h constants
	cryptENotFound = 0x80092004 // CRYPT_E_NOT_FOUND

	// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/bcrypt.h
	bCryptSupportedPadPkcs1End uintptr = 0x2
	bCryptPadPss               uintptr = 0x8

	// https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/crypto/rsa/pss.go;bpv=1;bpt=1
	pssSaltLengthEqualsHash = -1
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

func VerifyCertChainV3Cert(leafCert *x509.Certificate, rootCertPool *x509.CertPool) error {
	caCertPool := x509.NewCertPool()

	if len(leafCert.Extensions) > 0 {
		for _, ext := range leafCert.Extensions {
			if ext.Id.String() == "1.2.840.113556.1.8000.2554.197254.100" {
				log.Printf("client cert contains embedded CA")
				caCertPool.AppendCertsFromPEM(ext.Value)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: caCertPool,
	}

	_, err := leafCert.Verify(opts)
	return err
}

type WinCert struct {
	PublicCertFile string               // input: the public cert PEM file name
	storeHandle    *windows.Handle      // cert store handler
	x509cert       *x509.Certificate    // x509 certificate
	winCertContext *windows.CertContext // windows cert context
	privateKey     *uintptr             // private key handler
	refreshMutex   sync.Mutex           // mutex
}

// Create a new win cert object
// The requirements:
// 1. the public cert PEM file on the file system
// 2. the cert is imported to windows localmachine\My cert store
// 3. the cert has a CNG private key which can be used for signing
// 4. windows admin previledge is required to access localmachine\My cert store
// NOTE: currently, only RSA CNG private key is supported
func NewWinCert(conf *WinCert) (WinCert, error) {
	if conf.PublicCertFile == "" {
		return WinCert{}, fmt.Errorf("Public cert file name cannot be empty")
	}

	pubPEM, err := ioutil.ReadFile(conf.PublicCertFile)
	if err != nil {
		return WinCert{}, fmt.Errorf("Unable to read cert file: %v", err)
	}

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return WinCert{}, fmt.Errorf("Failed to parse PEM block: %s", conf.PublicCertFile)
	}

	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return WinCert{}, fmt.Errorf("Failed to parse certificat : %v", err)
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
		return WinCert{}, fmt.Errorf("CertOpenStore() failed for localmachine\\my store: %v", err)
	}

	certCxt, err := findCertViaThumbprint(store, pub)
	if err != nil {
		windows.CertCloseStore(store, 1)
		return WinCert{}, fmt.Errorf("Failed to find the cert in localmachine\\My specified by %s: %v", conf.PublicCertFile, err)
	}

	priv, err := certContextPrivateKey(certCxt)
	if err != nil {
		windows.CertCloseStore(store, 1)
		return WinCert{}, fmt.Errorf("Failed to find associated private key for cert context: %v", err)
	}

	conf.storeHandle = &store
	conf.x509cert = pub
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

// Core function to implement crypto.Signer
func (t *WinCert) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	log.Println("WinCert::Sign is called")

	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("Sign: Digest length doesn't match passed crypto algorithm")
	}

	hf := opts.HashFunc()
	algID, ok := algIDs[hf]
	if !ok {
		return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
	}

	var sig []byte
	var err error
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		log.Println("WinCert::signPSS is called")
		sig, err = signPSS(*t.privateKey, digest, hf, pssOpts)
		if err != nil {
			log.Printf("failed to sign RSA-signPSS %v\n", err)
			return nil, err
		}
	} else {
		log.Println("WinCert::signPKCS1v15 is called")
		sig, err = signPKCS1v15(*t.privateKey, digest, algID)
		if err != nil {
			log.Printf("failed to sign RSA-signPKCS1v15 %v\n", err)
			return nil, err
		}
	}

	log.Println("--result by WinCert private key")
	log.Printf("sig %s\n", hex.EncodeToString(sig))

	return sig, nil
}

// bCryptPkcs1PaddingInfo struct in bcrypt.h.
type bCryptPkcs1PaddingInfo struct {
	pszAlgID *uint16
}

func signPKCS1v15(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
	padInfo := bCryptPkcs1PaddingInfo{pszAlgID: algID}
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
		bCryptSupportedPadPkcs1End)
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
		bCryptSupportedPadPkcs1End)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

// bCryptPssPaddingInfo struct in bcrypt.h.
type bCryptPssPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   int
}

func signPSS(kh uintptr, digest []byte, hash crypto.Hash, pssOpts *rsa.PSSOptions) ([]byte, error) {
	if pssOpts.SaltLength != pssSaltLengthEqualsHash {
		return nil, fmt.Errorf("WinCert::signPSS: Only support pssSaltLengthEqualsHash for now")
	}

	padInfo := bCryptPssPaddingInfo{
		pszAlgID: algIDs[hash],
		cbSalt:   hash.Size(), // pssSaltLengthEqualsHash
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
		bCryptPadPss)
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
		bCryptPadPss)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	return sig[:size], nil
}

//  _CRYPTOAPI_BLOB struct in wincrypt.h.
type cryptHashBlob struct {
	cbData int
	pbData *byte
}

// findCertViaThumbprint wraps the CertFindCertificateInStore call. If no certificate was found, nil will be returned.
func findCertViaThumbprint(store windows.Handle, x509cert *x509.Certificate) (*windows.CertContext, error) {
	fingerprint := sha1.Sum(x509cert.Raw)
	log.Printf("Trying to find cert in the cert store with thumbprint '%s'\n", hex.EncodeToString(fingerprint[:]))
	thumbprint := cryptHashBlob{len(fingerprint), &fingerprint[0]}

	h, _, err := certFindCertificateInStore.Call(
		uintptr(store),
		uintptr(encodingX509ASN|encodingPKCS7),
		uintptr(0),
		uintptr(findSha1Hash),
		uintptr(unsafe.Pointer(&thumbprint)),
		uintptr(unsafe.Pointer(nil)),
	)

	if h == 0 {
		// Actual error, or simply not found?
		if errno, ok := err.(syscall.Errno); ok && errno == cryptENotFound {
			log.Printf("Could not find cert with thumbprint '%s'\n", hex.EncodeToString(fingerprint[:]))
			return nil, nil
		}
		return nil, err
	}

	log.Printf("Found cert with thumbprint '%s'\n", hex.EncodeToString(fingerprint[:]))
	return (*windows.CertContext)(unsafe.Pointer(h)), nil
}

// certContextPrivateKey wraps CryptAcquireCertificatePrivateKey. It obtains the CNG private
// key of a known certificate. When a nil cert context is passed
// a nil key is intentionally returned, to model the expected behavior of a
// non-existent cert having no private key.
// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
func certContextPrivateKey(cert *windows.CertContext) (*uintptr, error) {
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
