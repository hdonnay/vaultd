package main

// vim: set noexpandtab :

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	//"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	adminDefaultFile string      = "privkey.der"
	adminDefaultMode os.FileMode = 0600
	// while testing, set these low so as to not wait around a lot
	userKeySize      int  = 1024
	groupKeySize     int  = 1024
	validatorWorkers int  = 3
	DEVELOP          bool = true
)

// A User keeps their private key (safely, hopefully), and we keep the public key.
// A group stores their Public key alongside the symmetrically encrypted private key
// The ugm stores the group key, encrypted for each user
const initSQL string = `
BEGIN;
CREATE TABLE IF NOT EXISTS users (
	id       bigserial NOT NULL UNIQUE PRIMARY KEY,
	name     varchar(255),
	pubKey   bytea,
	creation timestamp,
	admin    boolean );
CREATE TABLE IF NOT EXISTS groups (
	id             bigserial NOT NULL UNIQUE PRIMARY KEY,
	name           varchar(255),
	pubKey         bytea,
	cryptedPrivKey bytea,
	hidden         boolean);
CREATE TABLE IF NOT EXISTS secret (
	id         bigserial NOT NULL UNIQUE PRIMARY KEY,
	uri        text,
	note       text,
	meta       text,
	ciphertext bytea );
CREATE TABLE IF NOT EXISTS ugm (
	id            bigserial NOT NULL UNIQUE PRIMARY KEY,
	userId        bigint REFERENCES users,
	groupId       bigint REFERENCES groups,
	cryptedSymKey bytea,
	admin         boolean );
CREATE TABLE IF NOT EXISTS gsm (
	id            bigserial NOT NULL UNIQUE PRIMARY KEY,
	groupId       bigint REFERENCES groups,
	secretId      bigint REFERENCES secret,
	cryptedSymKey bytea );
CREATE TEMP TABLE session (
	id        bigint,
	token     bytea,
	challenge bytea,
	expire    timestamp );
COMMIT; `

var l *log.Logger

var port int
var bind string
var forceInsecure bool
var dsn string
var httpsCert string
var httpsKey string

var query map[string]*sql.Stmt

func init() {
	l = log.New(os.Stdout, "", log.Lmicroseconds)
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&bind, "bind", "localhost", "Address to bind on")
	if DEVELOP {
		flag.BoolVar(&forceInsecure, "forceInsecure", true, "Force insecure (non-HTTPS) listening")
	} else {
		flag.BoolVar(&forceInsecure, "forceInsecure", false, "Force insecure (non-HTTPS) listening")
	}
	flag.StringVar(&dsn, "dsn", "host=/var/run/postgresql sslmode=disable", "postgres connection dsn")
	flag.StringVar(&httpsCert, "https cert", "cert.pem", "TLS cert for HTTP server")
	flag.StringVar(&httpsKey, "https cert key", "cert.key", "Key for TLS cert for HTTP server")
	flag.Parse()
}

func main() {
	l.Println("Initializing")

	l.Println("\tPreparing Database")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		l.Fatalf("Database open error: %s\n", err)
	}
	if err = db.Ping(); err != nil {
		l.Fatalf("Database connection error: %s\n", err)
	}
	_, err = db.Exec(initSQL)
	if err != nil {
		l.Fatal(err)
	}
	l.Println("\tDone")

	l.Println("\tPopulating queries")
	selId, err := db.Prepare("SELECT id FROM users WHERE name = $1")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	insChallenge, err := db.Prepare("INSERT INTO session (id, challenge, expire) VALUES ($1, $2, $3);")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	insToken, err := db.Prepare("INSERT INTO session (id, token, expire) VALUES ($1, $2, $3);")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	insUser, err := db.Prepare("INSERT INTO users (id, name, pubKey, creation, admin) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	insGroup, err := db.Prepare("INSERT INTO groups (id, name, pubKey, cryptedPrivKey, hidden) VALUES (default, $1, $2, $3, $4);")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	insUGM, err := db.Prepare("INSERT INTO ugm (id, userId, groupId, cryptedSymKey, admin) VALUES (default, $1, $2, $3, $4)")
	if err != nil {
		l.Fatalf("Failed to prepare query: %v\n", err)
	}
	l.Println("\tDone")

	l.Println("Done")

	sig := make(chan os.Signal, 1)
	propigate := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		l.Println("Caught SIGINT, cleaning up...")
		propigate <- os.Interrupt
		db.Close()
		l.Println("Googbye")
		os.Exit(0)
	}()

	var totalUsers int64
	err = db.QueryRow("SELECT count(*) FROM users").Scan(&totalUsers)
	if err != nil {
		l.Fatal(err)
	}
	l.Printf("Found %d users.\n", totalUsers)

	// if we have 0 users, we have 0 groups. We need an admin group.
	if totalUsers == 0 {
		var err error
		/*
			This chunk of code is an example for how parts are actually stored:
			 - PrivateKeys are stored in PKCS1 format
			 - PublicKeys are stored in PKIX format
			 - Symmetric encryption is done in CFB mode with the iv prepended to the ciphertext
			 - Asymmetric encryption is done via OAEP, using the public key's "owner" as the label
		*/
		l.Println("Database seems empty. Doing set-up:")
		// Make a 'root' superuser group
		l.Println("\tMaking 'root' group")

		groupPriv, err := rsa.GenerateKey(rand.Reader, groupKeySize)
		if err != nil {
			l.Fatal(err)
		}
		groupPubKey, _ := x509.MarshalPKIXPublicKey(&groupPriv.PublicKey)

		l.Println("\tNeed at least one admin user")
		l.Println("\t\tMaking 'defaultAdmin' user")
		// make a 'defaultAdmin' this user is meant to only be used in inital setup.
		userPriv, err := rsa.GenerateKey(rand.Reader, userKeySize)
		if err != nil {
			l.Fatal(err)
		}
		userPubKey, _ := x509.MarshalPKIXPublicKey(&userPriv.PublicKey)

		//store
		_, err = insUser.Exec("defaultAdmin", userPubKey, time.Now(), true)
		if err != nil {
			l.Fatal(err)
		}
		ioutil.WriteFile(adminDefaultFile, x509.MarshalPKCS1PrivateKey(userPriv), adminDefaultMode)
		l.Println("\t\tMade 'defaultAdmin' user")
		l.Printf("\t\t!!! Wrote private key to '%s' -- create a real admin user and delete the key.\n", adminDefaultFile)

		// make the symmetric key
		l.Println("\tNeed to store group's private key in escrow")
		l.Println("\t\tCreating symmetric key for private key")
		ugmKey := make([]byte, 32) //AES-256
		_, err = io.ReadFull(rand.Reader, ugmKey)
		if err != nil {
			l.Panic(err)
		}

		// do aes
		block, err := aes.NewCipher(ugmKey)
		if err != nil {
			l.Panic(err)
		}
		marshaledPrivKey := x509.MarshalPKCS1PrivateKey(groupPriv)
		ciphertext := make([]byte, aes.BlockSize+len(marshaledPrivKey))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			l.Panic(err)
		}

		mode := cipher.NewCFBEncrypter(block, iv)
		mode.XORKeyStream(ciphertext[aes.BlockSize:], marshaledPrivKey)

		_, err = insGroup.Exec("root", groupPubKey, ciphertext, true)
		if err != nil {
			l.Fatal(err)
		}
		l.Println("\tMade 'root' group.")

		cryptedSymKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &userPriv.PublicKey, ugmKey, []byte("defaultAdmin"))
		if err != nil {
			l.Fatal(err)
		}
		_, err = insUGM.Exec(1, 1, cryptedSymKey, true)
		if err != nil {
			l.Fatal(err)
		}
		l.Println("\t\tPlaced key in escrow.")
	}

	l.Println("Starting vaildator service...")
	validateChan := make(chan *validateRequest, validatorWorkers*2)
	q, err := db.Prepare("SELECT expire FROM session WHERE Id = $1 AND token = $2;")
	if err != nil {
		l.Fatalf("Failed to prepare validator query: %v\n", err)
	}
	del, err := db.Prepare("DELETE FROM session WHERE Id = $1 AND token = $2;")
	if err != nil {
		l.Fatalf("Failed to prepare validator delete query: %v\n", err)
	}
	for i := 0; i < validatorWorkers; i++ {
		go func(r chan *validateRequest, sig chan os.Signal) {
			for {
				select {
				case req := <-r:
					var expire time.Time
					err := q.QueryRow(req.Id, req.Token).Scan(&expire)
					if err != nil {
						l.Printf("Validator: %v\n", i, err)
						req.Reply <- false
						break
					}
					if time.Since(expire).Minutes() > float64(tokenExpire) {
						del.Exec(req.Id, req.Token)
					} else {
						req.Reply <- true
						break
					}
					req.Reply <- false
				case <-sig:
					return
				}
			}
		}(validateChan, propigate)
	}

	as :=&AuthService{
			ValidateService{validateChan},
			db,
			selId,
			insChallenge,
			insToken, }

	http.Handle("/", http.FileServer(http.Dir("static/")))
	http.HandleFunc("/api/login", as.Login)
	http.HandleFunc("/api/auth", as.Authenticate)
	http.HandleFunc("/api/valid", as.Valid)

	l.Printf("Starting Server on %s:%d\n", bind, port)
	if forceInsecure {
		l.Println("!!! Starting without HTTPS")
		l.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", bind, port), nil))
	} else {
		l.Fatal(http.ListenAndServeTLS("cert.pem", "cert.key", fmt.Sprintf("%s:%d", bind, port), nil))
	}
}
