package main

// vim: set noexpandtab :

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh/terminal"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

const (
	VERSION  string = "0.0.6-dev"
	jsonMime string = "application/json"
)

const (
	_             = iota
	E_SERVER uint = 1 << iota
	E_AUTH
	E_PASSPHRASE
	E_NOKEY
	E_BADKEY
)

var l *log.Logger

var forceUnencrypted bool
var forceInsecure bool
var DEBUG bool
var username string
var baseUrl string
var keyPath string
var keyFile string
var api map[string]*url.URL
var jar *cookiejar.Jar

type internalError struct {
	Code uint
}
func (i *internalError) Error() string {
	var ret string
	switch i.Code {
	case E_SERVER:
		ret = "vault: server returned HTTP 500"
	case E_AUTH:
		ret = "vault: could not authenticate"
	case E_PASSPHRASE:
		ret = "vault: bad passphrase"
	case E_NOKEY:
		ret = "vault: no key"
	case E_BADKEY:
		ret = "vault: key malformed/corrupted/(un)encrypted"
	default:
		ret = "vault: unknown error"
	}
	return ret
}

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func getPassphrase(prompt string) []byte {
	fmt.Fprintf(os.Stdout, prompt)
	phrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stdout, "\n")
	if err != nil {
		panic(err)
	}
	return phrase
}

func loadKey() (*rsa.PrivateKey, error) {
	var err error
	var der []byte
	i, err := os.Stat(keyFile)
	if err != nil {
		os.MkdirAll(keyPath, 0700)
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
		cryptedKey := ciphertext[aes.BlockSize:(len(ciphertext) - sha256.Size)]
		sig := ciphertext[(len(ciphertext) - sha256.Size):]
		der = make([]byte, len(cryptedKey))

		if _, err = io.ReadFull(f, ciphertext); err != nil {
			return nil, err
		}

		phrase := getPassphrase("Passphrase: ")
		io.Copy(h, bytes.NewReader(phrase))
		key := h.Sum(nil)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(der, cryptedKey)

		if !checkMAC(der, sig, key) {
			return nil, &internalError{E_BADKEY}
		}
	}
	privKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		if forceUnencrypted {
			fmt.Fprintf(os.Stderr, "Couldn't parse key. It's likely this key is encrypted.\n")
			return nil, &internalError{E_BADKEY}
		} else {
			return nil, err
		}
	}
	if forceUnencrypted {
		fmt.Fprintf(os.Stderr, "Encrypt this key with: '%s encrypt'\n", os.Args[0])
	}
	return privKey, nil
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
	cryptedKey := ciphertext[aes.BlockSize:(len(ciphertext) - sha256.Size)]
	sig := ciphertext[(len(ciphertext) - sha256.Size):]

	fmt.Fprintf(os.Stdout, "New Passphrase: ")
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

func login(privKey *rsa.PrivateKey) error {
	var err error
	c := make(map[string]string)
	// Step1: request challenge
	step1, err := json.Marshal(&map[string]string{"name": username})
	if err != nil {
		return err
	}
	resp, err := http.Post(api["login"].String(), jsonMime, strings.NewReader(string(step1)))
	if err != nil {
		return err
	}
//	if DEBUG {
//		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "login response", resp)
//	}
	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	d.Decode(&c)
	data := decodeBase64(c["challenge"])
	challenge, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, data, []byte(username))

	// Step2: validate challenge
	step2, err := json.Marshal(&map[string]string{"name": username, "token": base64.StdEncoding.EncodeToString(challenge)})
	if err != nil {
		return err
	}
	resp, err = http.Post(api["auth"].String(), jsonMime, strings.NewReader(string(step2)))
	if err != nil {
		return err
	}
//	if DEBUG {
//		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "auth response", resp)
//		for _, c := range resp.Cookies() {
//			fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "cookie:", c)
//		}
//	}
	if resp.StatusCode == http.StatusUnauthorized {
		return &internalError{E_AUTH}
	}
	if resp.StatusCode != http.StatusOK {
		return &internalError{E_SERVER}
	}

	jar.SetCookies(api["auth"], resp.Cookies())
	return nil
}

func isValid() bool {
	req, err := http.NewRequest("POST", api["valid"].String(), nil)
	if err != nil {
		l.Println("bad request")
		return false
	}
	for _, cookie := range jar.Cookies(api["auth"]) {
		req.AddCookie(cookie)
	}
//	if DEBUG {
//		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "cookies", req.Cookies())
//	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	return res.StatusCode == http.StatusOK
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "%s v%s -- Usage:\n\n", os.Args[0], VERSION)
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  help:\n    Print this help.\n\n")
	fmt.Fprintf(os.Stderr, "  test:\n    Run misc tests. For debugging.\n\n")
}

func init() {
	var logPath string
	flag.BoolVar(&forceUnencrypted, "forceUnencrypted", false, "Don't try to unencrypt key")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Don't use HTTPS to connect")
	flag.BoolVar(&DEBUG, "debug", false, "enable debugging output")
	flag.StringVar(&username, "username", os.Getenv("USER"), "Username")
	flag.StringVar(&baseUrl, "url", "http://localhost:8080", "Url to contact server at (excludes path)")
	flag.StringVar(&keyPath, "keyPath", fmt.Sprintf("%s/.config/vault/", os.Getenv("HOME")), "Path to the key")
	flag.StringVar(&logPath, "logPath", fmt.Sprintf("%s/.config/vault/", os.Getenv("HOME")), "Path to logfile")
	flag.Parse()
	keyFile = fmt.Sprintf("%skey", keyPath)
	os.MkdirAll(logPath, 0750)
	f, err := os.OpenFile(fmt.Sprintf("%slog", logPath), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open logfile: %s\n", fmt.Sprintf("%slog", logPath))
		os.Exit(1)
	}
	l = log.New(f, "", log.Lmicroseconds)
	l.Printf("vault client v%s started.\n", VERSION)
	// This is bad, need real options here
	jar, err = cookiejar.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed opening cookiejar: %v\n", err)
		os.Exit(1)
	}
	api = make(map[string]*url.URL)
	api["login"], _ = url.Parse(fmt.Sprintf("%s/api/login", baseUrl))
	api["auth"], _ = url.Parse(fmt.Sprintf("%s/api/auth", baseUrl))
	api["valid"], _ = url.Parse(fmt.Sprintf("%s/api/valid", baseUrl))
	if forceUnencrypted {
		fmt.Fprintf(os.Stderr, "Operating in 'forceUnencrypted' mode!\n")
	}
}

func main() {
	switch flag.Arg(0) {
	case "test":
		privKey, err := loadKey()
		if err != nil {
			l.Fatal(err)
		}
		if err = login(privKey); err != nil {
			l.Fatal(err)
		}
		if isValid() {
			fmt.Fprintf(os.Stderr, "Token is valid, successful login.\n")
		} else {
			fmt.Fprintf(os.Stderr, "Token isn't valid, unsuccessful login.\n")
			os.Exit(1)
		}
	case "reencrypt", "encrypt":
		privKey, err := loadKey()
		if err != nil {
			l.Fatal(err)
		}
		err = encryptKey(privKey)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(1)
		}
	case "help":
		fallthrough
	default:
		Usage()
		os.Exit(1)
	}
	os.Exit(0)
}
