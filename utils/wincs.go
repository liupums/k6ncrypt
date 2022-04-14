// https://github.com/salrashid123/signer/blob/master/example/sign_verify_pem/main.go
package utils

import (
	"fmt"
	"crypto"	
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"io"
	"encoding/hex"	
	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
	"unsafe"
	"unicode/utf16"
)

// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/bcrypt.h
const (
	BCRYPT_SUPPORTED_PAD_PKCS1_ENC uintptr = 0x2
	BCRYPT_PAD_PSS uintptr = 0x8
)

// wide returns a pointer to a a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

var (
	// algIDs maps crypto.Hash values to bcrypt.h constants.
	algIDs = map[crypto.Hash]*uint16{
		crypto.SHA1:   wide("SHA1"),   // BCRYPT_SHA1_ALGORITHM
		crypto.SHA256: wide("SHA256"), // BCRYPT_SHA256_ALGORITHM
		crypto.SHA384: wide("SHA384"), // BCRYPT_SHA384_ALGORITHM
		crypto.SHA512: wide("SHA512"), // BCRYPT_SHA512_ALGORITHM
	}

	crypt32 = windows.MustLoadDLL("crypt32.dll")
	nCrypt  = windows.MustLoadDLL("ncrypt.dll")

	certDeleteCertificateFromStore    = crypt32.MustFindProc("CertDeleteCertificateFromStore")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	certFreeCertificateChain          = crypt32.MustFindProc("CertFreeCertificateChain")
	certGetCertificateChain           = crypt32.MustFindProc("CertGetCertificateChain")
	certGetIntendedKeyUsage           = crypt32.MustFindProc("CertGetIntendedKeyUsage")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	cryptFindCertificateKeyProvInfo   = crypt32.MustFindProc("CryptFindCertificateKeyProvInfo")
	nCryptCreatePersistedKey          = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptDecrypt                     = nCrypt.MustFindProc("NCryptDecrypt")
	nCryptExportKey                   = nCrypt.MustFindProc("NCryptExportKey")
	nCryptFinalizeKey                 = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptFreeObject                  = nCrypt.MustFindProc("NCryptFreeObject")
	nCryptOpenKey                     = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptOpenStorageProvider         = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptGetProperty                 = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptSetProperty                 = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptSignHash                    = nCrypt.MustFindProc("NCryptSignHash")

	x509Crt   *x509.Certificate
)

// paddingInfo is the BCRYPT_PKCS1_PADDING_INFO struct in bcrypt.h.
type paddingInfo struct {
	pszAlgID *uint16
}

// paddingInfo is the  BCRYPT_PSS_PADDING_INFO struct in bcrypt.h.
type BCRYPT_PSS_PADDING_INFO struct {
	pszAlgID *uint16
	cbSalt int
}

type WINCS struct {
	crypto.Signer // implement crypto.Signer
	refreshMutex       sync.Mutex

	Issuer string
	ncryptkey certtostore.Key
}

// Just to test crypto.Singer, crypto.Decrypt interfaces
// the following Decrypt and Sign functions uses ordinary private keys

func NewWINCS(conf *WINCS) (WINCS, error) {
	if conf.Issuer == "" {
		return WINCS{}, fmt.Errorf("certstore cannot be empty")
	}

	// Open the local cert store. Provider generally shouldn't matter, so use Software which is ubiquitous. See comments in getHostKey.
	store, err := certtostore.OpenWinCertStore(certtostore.ProviderMSSoftware, "", []string{conf.Issuer}, nil, false)
	
	if err != nil {
		fmt.Errorf("OpenWinCertStore: %v", err)
		return WINCS{}, err
	}	
	
	fmt.Println("get cert from cert store")
	// Obtain the first cert matching all of container/issuers/intermediates in the store.
	// This function is indifferent to the provider the store was opened with, as the store lists certs
	// from all providers.
	crt, context, err := store.CertWithContext()
	if err != nil {
		fmt.Println("failed to get cert from cert store. ", err)
		return WINCS{}, err
	}
	
	if crt == nil {
		fmt.Println("no cert")
		return WINCS{}, fmt.Errorf("no cert found in certstore")
	}

	fmt.Println("get key from cert")
	// Obtain the private key from the cert. This *should* work regardless of provider because
	// the key is directly linked to the certificate.
	key, err := store.CertKey(context)
	if err != nil {
		fmt.Printf("private key not found in %s, %s", store.ProvName, err)
		return WINCS{}, err
	}

	if key == nil {
		fmt.Println("no key")
		return WINCS{}, fmt.Errorf("no key associated with cert")
	}

	fmt.Printf("find cert '%s' with private key in container '%s', algo '%s'\n", crt.Subject, key.Container, key.AlgorithmGroup)
	x509Crt = crt
    conf.ncryptkey = *key
	return *conf, nil
}

func (t WINCS) TLSCertificate() tls.Certificate {

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        x509Crt,
		Certificate: [][]byte{x509Crt.Raw},
	}
}

func (t WINCS) Public() crypto.PublicKey {
	return t.ncryptkey.Public().(crypto.PublicKey)
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
		cbSalt: hash.Size(), // PSSSaltLengthEqualsHash
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
func (t WINCS) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	fmt.Printf("Sign is called\n")

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
		fmt.Printf("SignPSS is called\n")
		sig, err = SignPSS(t.ncryptkey.TransientTpmHandle(), digest, hf, pssOpts)
		if err != nil {
			fmt.Printf("failed to sign RSA-SignPSS %v", err)
		}
	} else {
		fmt.Printf("SignPKCS1v15 is called\n")
		sig, err = SignPKCS1v15(t.ncryptkey.TransientTpmHandle(), digest, algID)
		if err != nil {
			fmt.Printf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
	}

	fmt.Printf("--result by winstore private key\n")		
	fmt.Printf("sig %s\n", hex.EncodeToString(sig))		
	fmt.Printf("-----\n")		

	return sig, nil
}
