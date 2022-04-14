// https://github.com/salrashid123/signer/blob/master/example/sign_verify_pem/main.go
package utils

import (
	"fmt"
	"crypto"	
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"sync"
	"encoding/pem"	
	"encoding/hex"	
	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
	"unsafe"
	"unicode/utf16"
)
const (
	// Legacy CryptoAPI flags
	bCryptPadPKCS1 uintptr = 0x2
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
)

// paddingInfo is the BCRYPT_PKCS1_PADDING_INFO struct in bcrypt.h.
type paddingInfo struct {
	pszAlgID *uint16
}

type WINCS struct {
	crypto.Signer // implement crypto.Signer

	PrivatePEMFile string
	privateKey *rsa.PrivateKey

	refreshMutex       sync.Mutex

	Issuer string
	ncryptkey uintptr
}

// Just to test crypto.Singer, crypto.Decrypt interfaces
// the following Decrypt and Sign functions uses ordinary private keys

func NewWINCS(conf *WINCS) (WINCS, error) {
	if conf.Issuer == "" {
		return WINCS{}, fmt.Errorf("certstore cannot be empty")
	}

	if conf.PrivatePEMFile == "" {
		return *conf, nil
	}

	privatePEM, err := ioutil.ReadFile(conf.PrivatePEMFile)
	if err != nil {
		return WINCS{}, fmt.Errorf("Unable to read keys %v", err)
	}

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return WINCS{}, fmt.Errorf("failed to parse PEM block containing the key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return WINCS{}, fmt.Errorf("Private Key must be RSA PKCS1 format: %v", err)
	}

	conf.privateKey = key
	return *conf, nil
}

func (t WINCS) TLSCertificate() tls.Certificate {
	// Open the local cert store. Provider generally shouldn't matter, so use Software which is ubiquitous. See comments in getHostKey.
	store, err := certtostore.OpenWinCertStore(certtostore.ProviderMSSoftware, "", []string{t.Issuer}, nil, false)
	
	if err != nil {
		fmt.Errorf("OpenWinCertStore: %v", err)
		return tls.Certificate{}
	}	
	
	fmt.Println("get cert from cert store")
	// Obtain the first cert matching all of container/issuers/intermediates in the store.
	// This function is indifferent to the provider the store was opened with, as the store lists certs
	// from all providers.
	crt, context, err := store.CertWithContext()
	if err != nil {
		fmt.Println("failed to get cert from cert store. ", err)
		return tls.Certificate{}
	}
	
	if crt == nil {
		fmt.Println("no cert")
		return tls.Certificate{}
	}

	fmt.Println("get key from cert")
	// Obtain the private key from the cert. This *should* work regardless of provider because
	// the key is directly linked to the certificate.
	key, err := store.CertKey(context)
	if err != nil {
		fmt.Printf("private key not found in %s, %s", store.ProvName, err)
		return tls.Certificate{}
	}

	if key == nil {
		fmt.Println("no key")
		return tls.Certificate{}
	}

	t.ncryptkey = key.TransientTpmHandle()

	fmt.Printf("find cert '%s' with private key in container '%s', algo '%s'\n", crt.Subject, key.Container, key.AlgorithmGroup)
	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        crt,
		Certificate: [][]byte{crt.Raw},
	}
}

func (t WINCS) Public() crypto.PublicKey {
	return t.privateKey.Public().(crypto.PublicKey)
}

func signRSA(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
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
		bCryptPadPKCS1)
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
		bCryptPadPKCS1)
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

	var signature []byte
	var err error
	// RSA-PSS: https://github.com/golang/go/issues/32425
	
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		fmt.Printf("SignPSS is called\n")
		signature, err = rsa.SignPSS(rand.Reader, t.privateKey, opts.HashFunc(), digest, pssOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	} else {
		fmt.Printf("SignPKCS1v15 is called\n")
		signature, err = rsa.SignPKCS1v15(rand.Reader, t.privateKey, opts.HashFunc(), digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
	}

	fmt.Printf("--result by pem private key\n")		
	fmt.Printf("digest %s\n", hex.EncodeToString(digest))		
	fmt.Printf("sig %s\n", hex.EncodeToString(signature))		
	fmt.Printf("-----\n")		

	hf := opts.HashFunc()
	algID, ok := algIDs[hf]
	if !ok {
		return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
	}

	sig, err := signRSA(t.ncryptkey, digest, algID)
	fmt.Printf("--result by winstore private key\n")		
	fmt.Printf("sig %s\n", hex.EncodeToString(sig))		
	fmt.Printf("-----\n")		

	return signature, nil
}
