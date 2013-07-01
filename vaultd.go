package main

// vim: set noexpandtab :

import (
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"
)

const (
	adminDefaultFile string      = "privkey.der"
	adminDefaultMode os.FileMode = 0600
	validatorWorkers int         = 3
	// while testing, set these low so as to not wait around a lot
	userKeySize  int = 1024
	groupKeySize int = 1024
)

// A User keeps their private key (safely, hopefully), and we keep the public key.
// A group stores their Public key alongside the symmetrically encrypted private key
// The ugm stores the group key, encrypted for each user
const initSQL string = `
SET timezone TO UTC;
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
DROP TABLE IF EXISTS session;
CREATE TABLE session (
	id        bigint,
	token     bytea,
	challenge bytea,
	expire    timestamp );
COMMIT; `

var l *log.Logger

var numCPU int
var port int
var bind string
var forceInsecure bool
var dsn string
var httpsCert string
var httpsKey string

func init() {
	l = log.New(os.Stdout, "", log.Lmicroseconds)
	flag.IntVar(&numCPU, "cpu", runtime.NumCPU(), "Number of CPUs to use")
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&bind, "bind", "localhost", "Address to bind on")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Force insecure (non-HTTPS) listening")
	flag.StringVar(&dsn, "dsn", "host=/var/run/postgresql sslmode=disable", "postgres connection dsn")
	flag.StringVar(&httpsCert, "https cert", "cert.pem", "TLS cert for HTTP server")
	flag.StringVar(&httpsKey, "https cert key", "cert.key", "Key for TLS cert for HTTP server")
	flag.Parse()
	runtime.GOMAXPROCS(numCPU)
}

func main() {
	l.Println("Initializing")

	l.Println("\tPreparing Database")
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		l.Fatalf("Database open error: %s\n", err)
	}
	if err = conn.Ping(); err != nil {
		l.Fatalf("Database connection error: %s\n", err)
	}
	_, err = conn.Exec(initSQL)
	if err != nil {
		l.Fatal(err)
	}

	db, err := NewDB(conn)
	if err != nil {
		l.Fatal(err)
	}

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
	err = conn.QueryRow("SELECT count(*) FROM users").Scan(&totalUsers)
	if err != nil {
		l.Fatal(err)
	}
	l.Printf("Found %d users.\n", totalUsers)

	// if we have 0 users, we have 0 groups. We need an admin group.
	if totalUsers == 0 {
		var err error
		l.Println("Database seems empty. Doing set-up:")
		// make a 'defaultAdmin' this user is meant to only be used in inital setup.
		uid, privKey, err := db.NewUser("defaultAdmin")
		if err != nil {
			l.Fatal(err)
		}
		err = ioutil.WriteFile("privkey.der", x509.MarshalPKCS1PrivateKey(privKey), 0777)
		if err != nil {
			l.Fatal(err)
		}
		l.Printf("!!! Wrote private key to '%s' -- create a real admin user and delete the key.\n", adminDefaultFile)
		_, err = db.NewGroup("root", uid)
		if err != nil {
			l.Fatal(err)
		}
	}

	l.Println("Starting vaildator service...")
	validateChan := make(chan *validateRequest, validatorWorkers*2)
	q, err := db.Prepare("SELECT expire FROM session WHERE id = $1 AND token = $2;")
	if err != nil {
		l.Fatalf("Failed to prepare validator query: %v\n", err)
	}
	del, err := db.Prepare("DELETE FROM session WHERE id = $1 AND token = $2;")
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
						l.Printf("Validator %d: %v\n", i, err)
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

	as := &AuthService{
		ValidateService{validateChan},
		conn,
		db.selUserId,
		db.insChallenge,
	}

	us := &UserService{
		ValidateService{validateChan},
		conn,
		db.insUser,
		db.insGroup,
		db.insUGM,
	}

	http.Handle("/", http.FileServer(http.Dir("static/")))
	http.HandleFunc("/api/login", as.Login)
	http.HandleFunc("/api/auth", as.Authenticate)
	http.HandleFunc("/api/valid", as.Valid)
	http.HandleFunc("/api/makeUser", us.MakeUser)

	srv := &http.Server{Addr: fmt.Sprintf("%s:%d", bind, port), ReadTimeout: time.Duration(60) * time.Second, WriteTimeout: time.Duration(60) * time.Second}
	l.Printf("Starting Server on %s:%d\n", bind, port)
	if forceInsecure {
		l.Println("!!! Starting without HTTPS")
		l.Fatal(srv.ListenAndServe())
	} else {
		l.Fatal(srv.ListenAndServeTLS(httpsCert, httpsKey))
	}
}
