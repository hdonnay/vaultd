package main

// vim: set noexpandtab :

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"hash"
	"strings"
	"net/http"
	"encoding/json"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"io"
	"io/ioutil"
	"code.google.com/p/go.crypto/ssh/terminal"
	"errors"
)

const (
	jsonMime string = "application/json"
)

var l *log.Logger
var e *log.Logger

var forceUnencrypted bool
var forceInsecure bool
var username string
var url string
var keyPath string
var keyFile string
var api map[string]string

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

func loadKey() (*rsa.PrivateKey, error) {
	var err error
	var der []byte
	i, err := os.Stat(keyFile)
	if err != nil {
		os.MkdirAll(keyPath, 0640)
		l.Fatalf("Couldn't find Private key, looked for %s\n", keyFile)
	}
	f, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	if forceUnencrypted {
		der = make([]byte, i.Size())
		if _, err = io.ReadFull(f, der); err != nil {
			return nil, err
		}
	} else {
		var h hash.Hash = sha256.New()
		var ciphertext []byte = make([]byte, i.Size())
		iv := ciphertext[:aes.BlockSize]
		cryptedKey := ciphertext[aes.BlockSize:(len(ciphertext)-sha256.Size)]
		sig := ciphertext[(len(ciphertext)-sha256.Size):]
		der = make([]byte, len(cryptedKey))

		if _, err = io.ReadFull(f, ciphertext); err != nil {
			return nil, err
		}

		fmt.Fprintf(os.Stdout, "Passphrase: ")
		phrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stdout, "\n")
		if err != nil {
			l.Fatal(err)
		}
		io.WriteString(h, string(phrase))
		key := h.Sum(nil)

		block, err := aes.NewCipher(key)
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(der, cryptedKey)

		if !checkMAC(der, sig, key) {
			return nil, errors.New("Corrupt key")
		}
	}
	privKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		if forceUnencrypted {
			fmt.Fprintf(os.Stderr, "Couldn't parse key. It's likely this key is encrypted.\n")
			l.Fatalf("unable to parse key: %v \n", err)
		} else {
			return nil, err
		}
	}
	if forceUnencrypted {
		fmt.Fprintf(os.Stderr, "Encrypt this key with: '%s encrypt'\n", os.Args[0])
	}
	return privKey, nil
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
// Store the given key in this format:
//
//     : aes iv :
//     : Encrypted PKCS1 Private Key :
//     : hmac-sha256 signature :
//
func encryptKey(privKey *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(privKey)
	var h hash.Hash = sha256.New()
	var ciphertext []byte = make([]byte, aes.BlockSize+len(der)+sha256.Size)
	iv := ciphertext[:aes.BlockSize]
	cryptedKey := ciphertext[aes.BlockSize:(len(ciphertext)-sha256.Size)]
	sig := ciphertext[(len(ciphertext)-sha256.Size):]

	fmt.Fprintf(os.Stdout, "Passphrase: ")
	phrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stdout, "\n")
	if err != nil {
		l.Fatal(err)
	}
	io.WriteString(h, string(phrase))
	key := h.Sum(nil)

	// write the iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		l.Println(err)
		return err
	}
	// Calculate the hmac signature
	mac := hmac.New(sha256.New, key)
	mac.Write(der)
	// write the hmac sig
	if _, err := io.ReadFull(bytes.NewReader(mac.Sum(nil)), sig); err != nil {
		l.Println(err)
		return err
	}

	block, err := aes.NewCipher(key)
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(cryptedKey, der)

	err = ioutil.WriteFile(keyFile, ciphertext, 0600)
	if err != nil {
		panic(err)
	}
	return nil
}

func login(privKey *rsa.PrivateKey) (string, error) {
	var err error
	c := make(map[string]string)
	// Step1: request challenge
	step1, err := json.Marshal(&map[string]string{"name": username})
	if err != nil {
		return "", err
	}
	resp, err := http.Post(api["login"], jsonMime, strings.NewReader(string(step1)))
	if err != nil {
		return "", err
	}
	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	d.Decode(&c)
	data := decodeBase64(c["challenge"])
	challenge, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, data, []byte(username))

	// Step2: validate challenge
	step2, err := json.Marshal(&map[string]string{"name": username, "token": base64.StdEncoding.EncodeToString(challenge)})
	if err != nil {
		return "", err
	}
	resp, err = http.Post(api["auth"], jsonMime, strings.NewReader(string(step2)))
	if err != nil {
		return "", err
	}
	e := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	e.Decode(&c)
	return c["token"], nil
}

func isValid(tok string) bool {
	// Step2: validate challenge
	payload, err := json.Marshal(&map[string]string{"name": username, "token": tok})
	if err != nil {
		l.Fatal("Validation Marshalling failed")
	}
	res, err := http.Post(api["valid"], jsonMime, strings.NewReader(string(payload)))
	if err != nil {
		return false
	}
	return res.StatusCode == http.StatusOK
}

var Usage = func() {
    fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
}

func init() {
	l = log.New(os.Stderr, "", log.Lmicroseconds | log.Lshortfile)
	e = log.New(os.Stderr, "", 0)
	flag.BoolVar(&forceUnencrypted, "forceUnencrypted", false, "Don't try to unencrypt key")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Don't use HTTPS to connect")
	flag.StringVar(&username, "username", os.Getenv("USER"), "Username")
	flag.StringVar(&url, "url", "http://localhost:8080", "Url to contact server at (excludes path)")
	flag.StringVar(&keyPath, "keyPath", fmt.Sprintf("%s/.config/vault/", os.Getenv("HOME")), "Path to the key")
	flag.Parse()
	keyFile = fmt.Sprintf("%s/key", keyPath)
	api = map[string]string{
		"login": fmt.Sprintf("%s/api/login", url),
		"auth": fmt.Sprintf("%s/api/auth", url),
		"valid": fmt.Sprintf("%s/api/valid", url),
	}
	if forceUnencrypted {
		fmt.Fprintf(os.Stderr, "Operating in 'forceUnencrypted' mode!\n")
	}
}

func main() {
	privKey, err := loadKey()
	if err != nil {
		l.Fatal(err)
	}
	switch flag.Arg(0) {
	case "test":
		tok, err := login(privKey)
		if err != nil {
			l.Fatal(err)
		}
		l.Printf("Is this token valid? %v\n", isValid(tok))
	case "encrypt":
		if !forceUnencrypted {
			fmt.Fprintf(os.Stdout, "This key is encrypted, skipping.\n")
			break
		}
		err = encryptKey(privKey)
		if err != nil {
			e.Fatal(err)
		}
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
	os.Exit(0)
}
