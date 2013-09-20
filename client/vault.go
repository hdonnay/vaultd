package main

// vim: set noexpandtab:

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh/terminal"
	//"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gokyle/cryptobox/box"
	"github.com/gokyle/cryptobox/secretbox"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	VERSION  string = "0.0.6-dev"
	jsonMime string = "application/json"
	_               = iota
	E_SERVER uint   = 1 << iota
	E_AUTH
	E_PASSPHRASE
	E_NOKEY
	E_BADKEY
)

var stdout *log.Logger

var forceInsecure bool
var DEBUG bool
var username string
var baseUrl string
var confPath string
var api map[string]*url.URL

var keyFile string
var myId int64
var client *http.Client
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

type User struct {
	Id   int64
	Name string
	//PubKey   box.PublicKey
	PubKey   []byte
	Creation time.Time
	Admin    bool
}

type Group struct {
	Id        int64
	Name      string
	Admin     []int64
	Member    []int64
	UserGroup bool
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
		log.Fatal(err)
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
		log.Fatal("key ContentLength <= 0")
	}
	// TODO: error check
	io.Copy(key, resp.Body)

	return box.PublicKey(key.Bytes()), nil
}

func loadKey() (box.PrivateKey, error) {
	var err error
	var raw []byte
	i, err := os.Stat(keyFile)
	if err != nil {
		os.MkdirAll(confPath, 0700)
		log.Fatalf("Couldn't find Private key, looked for %s\n", keyFile)
	}

	raw = make([]byte, i.Size())

	f, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(f, raw); err != nil {
		return nil, err
	}

	//if !box.KeyIsSuitable(raw) {
	//	phrase := getPassphrase("Passphrase: ")
	//	if !secretbox.KeyIsSuitable(phrase) {
	//		return nil, &internalError{E_BADKEY}
	//	}

	//	ret, ok := secretbox.Open(raw, secretbox.Key(phrase))
	//	if !ok {
	//		return nil, &internalError{E_BADKEY}
	//	}

	//	if !box.KeyIsSuitable(ret) {
	//		return nil, &internalError{E_BADKEY}
	//	}
	//	return box.PrivateKey(ret), nil
	//} else {
	stdout.Printf("This key is unencrypted!\nEncrypt this key with: '%s encrypt'\n", os.Args[0])
	return box.PrivateKey(raw), nil
	//}
}

func encryptKey(key box.PrivateKey) error {
	phrase := getPassphrase("New Passphrase: ")

	box, ok := secretbox.Seal([]byte(key), phrase)
	if !ok {
		return &internalError{E_BADKEY}
	}

	err := ioutil.WriteFile(keyFile, box, 0600)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func login(privKey box.PrivateKey) error {
	var err error
	var challenge []byte
	var ok bool
	var jar *cookiejar.Jar
	c := make(map[string]string)
	// Step1: request challenge
	resp, err := http.Get(fmt.Sprintf("%s/%s", api["auth"].String(), username))
	if err != nil {
		return err
	}
	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	d.Decode(&c)
	data := decodeBase64(c["challenge"])
	if box.BoxIsSigned(data) {
		log.Println("opening signed box...")
		challenge, ok = box.OpenAndVerify(data, privKey, srvKey)
	} else {
		log.Println("opening box...")
		challenge, ok = box.Open(data, privKey)
	}
	if !ok {
		log.Println("unboxing returned not ok")
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
	if resp.StatusCode == http.StatusUnauthorized {
		return &internalError{E_AUTH}
	}
	if resp.StatusCode != http.StatusOK {
		return &internalError{E_SERVER}
	}

	jar, err = cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Failed opening cookiejar: %v\n", err)
	}
	jar.SetCookies(api["/"], resp.Cookies())
	myId, _ = strconv.ParseInt(c["id"], 10, 64)
	client = &http.Client{Jar: jar}

	return nil
}

func isValid() bool {
	res, err := client.Get(api["valid"].String())
	if err != nil {
		return false
	}
	return res.StatusCode == http.StatusOK
}

func fetchUser(id int64) (*User, error) {
	var u User = User{}
	res, err := client.Get(fmt.Sprintf("%s/%d", api["user"].String(), id))
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(res.Body)
	defer res.Body.Close()
	d.Decode(&u)
	return &u, nil
}

func searchUser(name string) ([]int64, error) {
	var u struct{ Id []int64 }
	v := url.Values{}
	v.Set("name", name)
	res, err := client.Get(fmt.Sprintf("%s?%s", api["user"].String(), v.Encode()))
	log.Print(res)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(res.Body)
	defer res.Body.Close()
	d.Decode(&u)
	return u.Id, nil
}

func fetchGroup(id int64) (*Group, error) {
	var g Group = Group{}
	return &g, nil
}

func searchGroup(name string) (*Group, error) {
	return fetchGroup(0)
}

func createUser(name string, groups []int64, admin bool) error {
	type body struct {
		Admin  bool
		Name   string
		Groups []int64
	}
	b, err := json.Marshal(&body{Admin: admin, Name: name, Groups: groups})
	if err != nil {
		return err
	}
	resp, err := client.Post(api["user"].String(), jsonMime, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	log.Print(resp)
	return nil
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
	//var err error
	var conf string = os.Getenv("XDG_CONFIG_HOME")
	if conf == "" {
		conf = os.ExpandEnv("$HOME/.config")
	}

	log.SetFlags(0)
	log.SetOutput(os.Stderr)
	stdout = log.New(os.Stdout, "", 0)

	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Don't use HTTPS to connect")
	flag.BoolVar(&DEBUG, "debug", false, "enable debugging output")
	flag.StringVar(&username, "username", os.Getenv("USER"), "Username")
	flag.StringVar(&baseUrl, "url", "http://localhost:8080", "Url to contact server at (excludes path)")
	flag.StringVar(&confPath, "conf", fmt.Sprintf("%s/vault/", conf), "Path to configs and key")
	flag.Parse()

	if sha512.Size384 != secretbox.KeySize {
		log.Fatalf("Hash size and key size mismatch: %d != %d\n", sha512.Size384, secretbox.KeySize)
	}

	// This is bad, need real options here
	keyFile = fmt.Sprintf("%skey", confPath)

	api = make(map[string]*url.URL)
	api["/"], _ = url.Parse(baseUrl)
	api["key"], _ = url.Parse(fmt.Sprintf("%s/key", baseUrl))
	api["auth"], _ = url.Parse(fmt.Sprintf("%s/api/auth", baseUrl))
	api["valid"], _ = url.Parse(fmt.Sprintf("%s/api/noop", baseUrl))
	api["user"], _ = url.Parse(fmt.Sprintf("%s/api/user", baseUrl))
}

func main() {
	if flag.Arg(0) == "help" {
		Usage()
		os.Exit(1)
	}
	privKey, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}
	srvKey, err := fetchServerKey()
	if err != nil {
		log.Fatalf("Can't fetch server key: %v\n", err)
	}
	if DEBUG {
		log.Printf("server public key: %x\n", srvKey)
	}
	switch flag.Arg(0) {
	case "test":
		var me *User
		if err = login(privKey); err != nil {
			log.Fatal(err)
		}
		if isValid() {
			stdout.Printf("Token is valid, successful login.\n")
		} else {
			stdout.Fatalf("Token isn't valid, unsuccessful login.\n")
		}
		me, err = fetchUser(myId)
		if err != nil {
			log.Fatalf("Could not fetch self: %v\n", err)
		} else {
			log.Printf("Fetched self!: %+v\n", me)
		}
	case "user":
		if err = login(privKey); err != nil {
			log.Fatal(err)
		}
		switch flag.Arg(1) {
		case "new":
			var group []int64 = make([]int64, 0)
			newU := flag.NewFlagSet("user new", flag.ExitOnError)
			admin := *newU.Bool("admin", false, "Should user be an admin")
			groupStr := strings.Split(*newU.String("groups", "", "Additional groups to add a user to"), ",")
			newU.Parse(flag.Args()[2:])
			if newU.NArg() != 1 {
				log.Fatalf("Wrong number of arguments!\n")
			}
			for _, v := range groupStr {
				g, err := searchGroup(v)
				if err != nil {
					log.Printf("Can't find group '%s', skipping...\n", v)
					continue
				}
				group = append(group, g.Id)
			}

			err := createUser(newU.Arg(0), group, admin)
			if err != nil {
				log.Fatal(err)
			}
		case "search":
			u, err := searchUser(flag.Arg(2))
			if err != nil {
				log.Fatal(err)
			}
			log.Print(u)
		default:
			log.Println("HELP")
		}
	case "reencrypt", "encrypt":
		err = encryptKey(privKey)
		if err != nil {
			log.Fatal(err)
		}
	default:
		Usage()
	}
	os.Exit(0)
}
