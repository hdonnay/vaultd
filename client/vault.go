package main

// vim: set noexpandtab :

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh/terminal"
	//"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"github.com/gokyle/cryptobox/box"
	"github.com/gokyle/cryptobox/secretbox"
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
var srvKey box.PublicKey

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

func getPassphrase(prompt string) []byte {
	var h hash.Hash = sha512.New384()
	fmt.Fprintf(os.Stdout, prompt)
	phrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintf(os.Stdout, "\n")
	if err != nil {
		panic(err)
	}
	io.Copy(h, bytes.NewReader(phrase))
	return h.Sum(nil)
}

func fetchServerKey() (box.PublicKey, error) {
	var key *bytes.Buffer = new(bytes.Buffer)
	resp, err := http.Get(api["key"].String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength <= 0 {
		l.Fatal("key ContentLength <= 0")
	}
	io.Copy(key, resp.Body)

	return box.PublicKey(key.Bytes()), nil
}
func loadKey() (box.PrivateKey, error) {
	var err error
	var raw []byte
	i, err := os.Stat(keyFile)
	if err != nil {
		os.MkdirAll(keyPath, 0700)
		l.Fatalf("Couldn't find Private key, looked for %s\n", keyFile)
	}

	raw = make([]byte, i.Size())

	f, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(f, raw); err != nil {
		return nil, err
	}

	if !forceUnencrypted {
		phrase := getPassphrase("Passphrase: ")
		ok := secretbox.KeyIsSuitable(phrase)
		if !ok {
			return nil, &internalError{E_BADKEY}
		}

		ret, ok := secretbox.Open(raw, secretbox.Key(phrase))
		if !ok {
			return nil, &internalError{E_BADKEY}
		}

		return box.PrivateKey(ret), nil
	} else {
		fmt.Fprintf(os.Stderr, "Encrypt this key with: '%s encrypt'\n", os.Args[0])
		return box.PrivateKey(raw), nil
	}
}

func encryptKey(key box.PrivateKey) error {
	phrase := getPassphrase("New Passphrase: ")

	box, ok := secretbox.Seal([]byte(key), phrase)
	if !ok {
		return &internalError{E_BADKEY}
	}

	err := ioutil.WriteFile(keyFile, box, 0600)
	if err != nil {
		l.Fatal(err)
	}
	return nil
}

func login(privKey box.PrivateKey) error {
	var err error
	var challenge []byte
	var ok bool
	c := make(map[string]string)
	// Step1: request challenge
	resp, err := http.Get(fmt.Sprintf("%s/%s", api["auth"].String(), username))
	if err != nil {
		return err
	}
	if DEBUG {
		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "login response", resp)
	}
	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	d.Decode(&c)
	l.Printf("challenge:\t%v\n", c["challenge"])
	l.Printf("id:\t%v\n", c["id"])
	data := decodeBase64(c["challenge"])
	if box.BoxIsSigned(data) {
		l.Println("opening signed box...")
		challenge, ok = box.OpenAndVerify(data, privKey, srvKey)
	} else {
		l.Println("opening box...")
		challenge, ok = box.Open(data, privKey)
	}
	if !ok {
		l.Println("Box returned not ok")
		return &internalError{E_AUTH}
	}

	// Step2: validate challenge
	step2, err := json.Marshal(&map[string]string{"id": c["id"], "challenge": base64.StdEncoding.EncodeToString(challenge)})
	if err != nil {
		return err
	}
	resp, err = http.Post(api["auth"].String(), jsonMime, strings.NewReader(string(step2)))
	if err != nil {
		return err
	}
	if DEBUG {
		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "auth response", resp)
		for _, c := range resp.Cookies() {
			fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "cookie:", c)
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return &internalError{E_AUTH}
	}
	if resp.StatusCode != http.StatusOK {
		return &internalError{E_SERVER}
	}

	jar.SetCookies(api["/"], resp.Cookies())
	return nil
}

func isValid() bool {
	req, err := http.NewRequest("GET", api["valid"].String(), nil)
	if err != nil {
		l.Println("bad request")
		return false
	}
	for _, cookie := range jar.Cookies(api["auth"]) {
		req.AddCookie(cookie)
	}
	if DEBUG {
		fmt.Fprintf(os.Stderr, "DEBUG: %s\n%v\n\n", "cookies", req.Cookies())
	}
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
	var err error
	var f *os.File
	var conf string = os.Getenv("XDG_CONFIG_HOME")
	if conf == "" {
		conf = os.ExpandEnv("$HOME/.config")
	}

	flag.BoolVar(&forceUnencrypted, "forceUnencrypted", false, "Don't try to unencrypt key")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Don't use HTTPS to connect")
	flag.BoolVar(&DEBUG, "debug", false, "enable debugging output")
	flag.StringVar(&username, "username", os.Getenv("USER"), "Username")
	flag.StringVar(&baseUrl, "url", "http://localhost:8080", "Url to contact server at (excludes path)")
	flag.StringVar(&keyPath, "keyPath", fmt.Sprintf("%s/vault/", conf), "Path to the key")
	flag.StringVar(&logPath, "logPath", fmt.Sprintf("%s/vault/", conf), "Path to logfile")
	flag.Parse()

	if sha512.Size384 != secretbox.KeySize {
		l.Fatalf("Hash size and key size mismatch: %d != %d\n", sha512.Size384, secretbox.KeySize)
	}

	if !DEBUG {
		os.MkdirAll(logPath, 0750)
		f, err = os.OpenFile(fmt.Sprintf("%slog", logPath), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't open logfile: %s\n", fmt.Sprintf("%slog", logPath))
			os.Exit(1)
		}
	} else {
		f = os.Stderr
	}
	l = log.New(f, "", log.Lmicroseconds)

	keyFile = fmt.Sprintf("%skey", keyPath)
	// This is bad, need real options here
	jar, err = cookiejar.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed opening cookiejar: %v\n", err)
		os.Exit(1)
	}
	api = make(map[string]*url.URL)
	api["/"], _ = url.Parse(baseUrl)
	api["key"], _ = url.Parse(fmt.Sprintf("%s/key", baseUrl))
	api["auth"], _ = url.Parse(fmt.Sprintf("%s/api/auth", baseUrl))
	api["valid"], _ = url.Parse(fmt.Sprintf("%s/api/noop", baseUrl))
	if forceUnencrypted {
		fmt.Fprintf(os.Stderr, "Operating in 'forceUnencrypted' mode!\n")
	}
}

func main() {
	srvKey, err := fetchServerKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't fetch server key: %v\n", err)
		l.Fatal(err)
	}
	if DEBUG {
		l.Printf("server public key: %x\n", srvKey)
	}
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
