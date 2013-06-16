package main

// vim: set noexpandtab :

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json2"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	adminDefaultFile string      = "privkey.der"
	adminDefaultMode os.FileMode = 0777
	userKeySize      int         = 4096
	groupKeySize     int         = 2048
	//DEVELOP bool = true
)

var l *log.Logger

var port int
var bind string
var forceInsecure bool
var dsn string

var query map[string]string

func init() {
	l = log.New(os.Stdout, "", log.Lmicroseconds)
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&bind, "bind", "localhost", "Address to bind on")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Force insecure (non-HTTPS) listening")
	flag.StringVar(&dsn, "dsn", "host=/var/run/postgresql sslmode=disable", "postgres connection dsn")
	flag.Parse()
	l.Println("Initializing")
	l.Println("Populating queries")
	// A User keeps their private key (safely, hopefully), and we keep the public key.
	query = map[string]string{
		"init": `CREATE TABLE IF NOT EXISTS users (
				id       bigserial NOT NULL UNIQUE PRIMARY KEY,
				name     varchar(255),
				pubKey   bytea,
				creation timestamp,
				admin    boolean );
			CREATE TABLE IF NOT EXISTS groups (
				id     bigserial NOT NULL UNIQUE PRIMARY KEY,
				name   varchar(255),
				pubKey bytea,
				hidden boolean);
			CREATE TABLE IF NOT EXISTS secret (
				id         bigserial NOT NULL UNIQUE PRIMARY KEY,
				uri        text,
				note       text,
				meta       text,
				ciphertext bytea );
			CREATE TABLE IF NOT EXISTS ugm (
				id             bigserial NOT NULL UNIQUE PRIMARY KEY,
				userId         bigint REFERENCES users,
				groupId        bigint REFERENCES groups,
				cryptedPrivKey bytea,
				admin          boolean );
			CREATE TABLE IF NOT EXISTS gsm (
				id            bigserial NOT NULL UNIQUE PRIMARY KEY,
				groupId       bigint REFERENCES groups,
				secretId      bigint REFERENCES secret,
				cryptedSymKey bytea );
			CREATE TEMP TABLE session (
				id        bigint,
				token     bytea,
				challenge bytea,
				expire    timestamp );`,
		"setUser":  "INSERT INTO users (id, name, pubKey, creation, admin) VALUES (default, $1, $2, $3, $4);",
		"setGroup": "INSERT INTO groups (id, name, pubKey, hidden) VALUES (default, $1, $2, $3);",
		"setUGM":   "INSERT INTO ugm (id, userId, groupId, cryptedPrivKey) VALUES (default, $1, $2, $3)",
	}
	l.Println("Done")
}

func main() {
	l.Println("Preparing Database")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		l.Fatalf("Database open error: %s\n", err)
	}
	if err = db.Ping(); err != nil {
		l.Fatalf("Database connection error: %s\n", err)
	}

	_, err = db.Exec(query["init"])
	if err != nil {
		l.Fatal(err)
	}
	l.Println("Database Initialized")

	var totalUsers int64
	err = db.QueryRow("SELECT count(*) FROM users").Scan(&totalUsers)
	if err != nil {
		l.Fatal(err)
	}
	l.Printf("Found %d users.\n", totalUsers)

	if totalUsers == 0 {
		var res sql.Result
		var err error
		l.Println("That number seems low. Making you a fresh admin user...")
		groupPriv, err := rsa.GenerateKey(rand.Reader, userKeySize)
		if err != nil {
			l.Fatal(err)
		}
		groupPubKey, _ := x509.MarshalPKIXPublicKey(&groupPriv.PublicKey)
		res, err = db.Exec(query["setGroup"], "root", groupPubKey, true)
		if err != nil {
			l.Fatal(err)
		}
		groupId, _ := res.LastInsertId()
		l.Println("Made 'root' group.")
		userPriv, err := rsa.GenerateKey(rand.Reader, groupKeySize)
		if err != nil {
			l.Fatal(err)
		}
		userPubKey, _ := x509.MarshalPKIXPublicKey(&userPriv.PublicKey)
		res, err = db.Exec(query["setUser"], "defaultAdmin", userPubKey, time.Now(), true)
		if err != nil {
			l.Fatal(err)
		}
		userId, _ := res.LastInsertId()
		l.Println("Made 'defaultAdmin' user.")
		cryptedPrivKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &userPriv.PublicKey, x509.MarshalPKCS1PrivateKey(groupPriv), []byte("defaultAdmin"))
		if err != nil {
			l.Fatal(err)
		}
		res, err = db.Exec(query["setUGM"], userId, groupId, cryptedPrivKey)
		if err != nil {
			l.Fatal(err)
		}
		l.Println("Mapping made.")
		ioutil.WriteFile(adminDefaultFile, x509.MarshalPKCS1PrivateKey(userPriv), adminDefaultMode)
		l.Printf("Wrote private key to '%s' -- create a real admin user and delete the key.\n", adminDefaultFile)
	}

	l.Printf("Starting Server on %s:%d\n", bind, port)
	r := rpc.NewServer()
	r.RegisterCodec(json2.NewCodec(), "application/json")
	r.RegisterService(new(PingService), "Ping")
	r.RegisterService(&AuthService{DB: db}, "Auth")
	s := mux.NewRouter()
	s.Handle("/", http.FileServer(http.Dir("static/")))
	s.HandleFunc("/rest/", RootHandler)
	http.Handle("/rpc", r)
	http.Handle("/", s)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		l.Println("Caught a signal")
		db.Close()
		l.Println("Googbye")
		os.Exit(0)
	}()

	if forceInsecure {
		l.Println("!!! Starting without HTTPS")
		l.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", bind, port), nil))
	} else {
		l.Fatal(http.ListenAndServeTLS("cert.pem", "cert.key", fmt.Sprintf("%s:%d", bind, port), nil))
	}
}
