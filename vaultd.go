package main

// vim: set noexpandtab :

import (
	//"crypto/tls"
	//"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/emicklei/go-restful"
	"github.com/gokyle/cryptobox/box"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"time"
	"io"
	"bytes"
)

const (
	adminDefaultFile string      = "defaultAdmin.key"
	adminDefaultMode os.FileMode = 0600
	validatorWorkers int         = 3
	// while testing, set these low so as to not wait around a lot
	userKeySize  int = 1024
	groupKeySize int = 1024
)

var l *log.Logger

var port int
var bind string
var forceInsecure bool
var dsn string
var caCert string
var httpsCert string
var httpsKey string
var boxPriv box.PrivateKey
var boxPub box.PublicKey

var db *sql.DB
var q map[string]*sql.Stmt

func init() {
	var err error
	var dbver string

	var boxPrivFile, boxPubFile string

	l = log.New(os.Stdout, "", log.Lmicroseconds)
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&bind, "bind", "localhost", "Address to bind on")
	flag.BoolVar(&forceInsecure, "forceInsecure", false, "Force insecure (non-HTTPS) listening")
	flag.StringVar(&dsn, "dsn", "host=/var/run/postgresql sslmode=disable", "postgres connection dsn")
	flag.StringVar(&caCert, "ca", "ca.pem", "CA cert (used for client certificates)")
	flag.StringVar(&httpsCert, "cert", "cert.pem", "TLS cert for HTTP server")
	flag.StringVar(&httpsKey, "key", "cert.key", "Key for TLS cert for HTTP server")
	flag.StringVar(&boxPrivFile, "priv", "priv.der", "Server private key (for signing")
	flag.StringVar(&boxPubFile, "pub", "pub.der", "Server public key (for signing")
	flag.Parse()

	l.Println("Initializing")

	_, privErr := os.Stat(boxPrivFile)
	_, pubErr := os.Stat(boxPubFile)

	switch {
	case privErr != nil && pubErr != nil:
		pr, pu, ok := box.GenerateKey()
		if !ok {
			l.Fatal("Error generating key")
		}
		boxPriv = pr
		boxPub = pu
		ioutil.WriteFile(boxPrivFile, []byte(pr), 0600)
		ioutil.WriteFile(boxPubFile, []byte(pu), 0600)
	case privErr != nil || pubErr != nil:
		l.Fatal("Only one file of the public/private keypair exists.")
	default:
		t, err := ioutil.ReadFile(boxPrivFile)
		if err != nil {
			l.Fatalf("Error opening keyfile: %v\n", err)
		}
		boxPriv = box.PrivateKey(t)

		t, err = ioutil.ReadFile(boxPubFile)
		if err != nil {
			l.Fatalf("Error opening keyfile: %v\n", err)
		}
		boxPub = box.PublicKey(t)
	}
	l.Printf("Loaded signing key: %x (length %d)\n", boxPub, len(boxPub))

	db, err = sql.Open("postgres", dsn)
	if err != nil {
		l.Fatalf("Database open error: %s\n", err)
	}
	if err = db.Ping(); err != nil {
		l.Fatalf("Database connection error: %s\n", err)
	}
	l.Println("\tPreparing Database")
	err = db.QueryRow("SELECT version();").Scan(&dbver)
	l.Printf("DB reports version: %s\n", dbver)

	err = dbInit(db)
	if err != nil {
		l.Fatal(err)
	}
}

func main() {
	var err error
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
		l.Println("Database seems empty. Doing set-up:")
		// make a 'defaultAdmin' this user is meant to only be used in inital setup.
		err, u, privKey := NewUser("defaultAdmin", true)
		if err != nil {
			l.Fatal(err)
		}
		err = ioutil.WriteFile(adminDefaultFile, *privKey, adminDefaultMode)
		if err != nil {
			l.Fatal(err)
		}
		l.Printf("!!! Wrote private key to '%s' -- create a real admin user and delete the key.\n", adminDefaultFile)
		err, _ = NewGroup("root", u.Id, true)
		if err != nil {
			l.Fatal(err)
		}
	}

	ws := new(restful.WebService)
	ws.Route(ws.GET("/key").
		Produces("application/octect-stream").
		To(func(req *restful.Request, resp *restful.Response) {
			io.Copy(resp, bytes.NewReader([]byte( boxPub)))
		}))
	ws.Route(ws.GET("/{x}").
		To(func(req *restful.Request, resp *restful.Response) {
			http.ServeFile(
				resp.ResponseWriter,
				req.Request,
				path.Join("static/", req.PathParameter("x")))
		}))

	api := new(restful.WebService)
	api.Path("/api")
	api.Consumes(restful.MIME_JSON)
	api.Produces(restful.MIME_JSON)

	api.Route( api.GET("/auth/{name}").
		//Filter(checkAuthentication).
		To(getChallenge).
		Doc("Request a challenge token.").
		Param(api.PathParameter("name", "Username to request a challenge for").DataType("string")))
	api.Route( api.POST("/auth").
		To(postChallenge).
		Doc("Validate challenge token"))

	/*
	http.HandleFunc("/api/login", as.Login)
	http.HandleFunc("/api/auth", as.Authenticate)
	http.HandleFunc("/api/valid", as.Valid)
	http.HandleFunc("/api/makeUser", us.MakeUser)
	*/

	restful.Add(ws)
	restful.Add(api)
	l.Printf("Starting Server on %s:%d\n", bind, port)
	srv := &http.Server{Addr: fmt.Sprintf("%s:%d", bind, port), ReadTimeout: time.Duration(60) * time.Second, WriteTimeout: time.Duration(60) * time.Second}
	l.Fatal(srv.ListenAndServe())
}
