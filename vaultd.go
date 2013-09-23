package main

// vim: set noexpandtab:

import (
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"github.com/emicklei/go-restful"
	"github.com/gokyle/cryptobox/box"
	"github.com/golang/glog"
	_ "github.com/lib/pq"
	"io"
	"io/ioutil"
	"net/http"
	//remove when not debugging
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"text/tabwriter"
	"time"
)

const (
	adminDefaultFile string      = "defaultAdmin.key"
	adminDefaultMode os.FileMode = 0600
	validatorWorkers int         = 3
	// while testing, set these low so as to not wait around a lot
	userKeySize  int = 1024
	groupKeySize int = 1024
)

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

	glog.Info("Initializing")

	_, privErr := os.Stat(boxPrivFile)
	_, pubErr := os.Stat(boxPubFile)

	switch {
	case privErr != nil && pubErr != nil:
		pr, pu, ok := box.GenerateKey()
		if !ok {
			glog.Fatal("Error generating key")
		}
		boxPriv = pr
		boxPub = pu
		ioutil.WriteFile(boxPrivFile, []byte(pr), 0600)
		ioutil.WriteFile(boxPubFile, []byte(pu), 0600)
	case privErr != nil || pubErr != nil:
		glog.Fatal("Only one file of the public/private keypair exists.")
	default:
		t, err := ioutil.ReadFile(boxPrivFile)
		if err != nil {
			glog.Fatalf("Error opening keyfile: %v\n", err)
		}
		boxPriv = box.PrivateKey(t)

		t, err = ioutil.ReadFile(boxPubFile)
		if err != nil {
			glog.Fatalf("Error opening keyfile: %v\n", err)
		}
		boxPub = box.PublicKey(t)
	}
	if glog.V(1) {
		glog.Infof("Loaded signing key: %x (length %d)\n", boxPub, len(boxPub))
	}

	db, err = sql.Open("postgres", dsn)
	if err != nil {
		glog.Fatalf("Database open error: %s\n", err)
	}
	if err = db.Ping(); err != nil {
		glog.Fatalf("Database connection error: %s\n", err)
	}
	err = db.QueryRow("SELECT version();").Scan(&dbver)
	if glog.V(1) {
		glog.Infof("DB reports version: %s\n", dbver)
	}

	err = dbInit(db)
	if err != nil {
		glog.Fatal(err)
	}
}

func main() {
	var err error
	sig := make(chan os.Signal, 1)
	propigate := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		glog.Infoln("Caught SIGINT, cleaning up...")
		propigate <- os.Interrupt
		db.Close()
		glog.Infoln("Googbye")
		glog.Flush()
		os.Exit(0)
	}()

	var totalUsers int64
	err = db.QueryRow("SELECT count(*) FROM users").Scan(&totalUsers)
	if err != nil {
		glog.Fatal(err)
	}
	if glog.V(1) {
		glog.Infof("Found %d users.\n", totalUsers)
	}

	// if we have 0 users, we have 0 groups. We need an admin group.
	if totalUsers == 0 {
		var err error
		glog.Warningln("Database seems empty. Doing set-up:")
		// make a 'defaultAdmin' this user is meant to only be used in inital setup.
		err, u, privKey := NewUser("defaultAdmin", true)
		if err != nil {
			glog.Fatal(err)
		}
		err = ioutil.WriteFile(adminDefaultFile, privKey, adminDefaultMode)
		if err != nil {
			glog.Fatal(err)
		}
		glog.Warningf("Wrote private key to '%s' -- create a real admin user and delete the key.\n", adminDefaultFile)
		err, _ = NewGroup("root", u.Id, false)
		if err != nil {
			glog.Fatal(err)
		}
	}

	ws := new(restful.WebService)
	ws.Route(ws.GET("/key").Produces("application/octect-stream").To(func(req *restful.Request, resp *restful.Response) { io.Copy(resp, bytes.NewReader([]byte(boxPub))) }))
	ws.Route(ws.GET("/{x}").To(func(req *restful.Request, resp *restful.Response) {
		http.ServeFile(resp.ResponseWriter, req.Request, path.Join("static/", req.PathParameter("x")))
	}))

	api := new(restful.WebService)
	api.Path("/api")
	api.Consumes(restful.MIME_JSON)
	api.Produces(restful.MIME_JSON)

	api.Route(api.GET("/auth/{name}").To(getChallenge).
		Doc("Request a challenge token.").
		Param(api.PathParameter("name", "Username to request a challenge for").DataType("string")))
	api.Route(api.POST("/auth").To(postChallenge).
		Doc("Submit decrypted challenge token"))

	api.Route(api.GET("/noop").Filter(checkAuthentication).To(func(req *restful.Request, resp *restful.Response) { return }).Doc("Check Authentication"))

	// Right now, inline documentation at the expense of readability.
	api.Route(api.GET("/user").Filter(checkAuthentication).Filter(checkAuthorization).To(searchUser).
		Doc("Search for users.").
		Param(api.QueryParameter("name", "Name to search for").DataType("string")))
	api.Route(api.POST("/user").Filter(checkAuthentication).Filter(checkAuthorization).To(createUser).
		Doc("Make user.").
		Param(api.BodyParameter("admin", "Should user be a global admin?").DataType("boolean")).
		Param(api.BodyParameter("name", "Name for user.").DataType("string")).
		Param(api.BodyParameter("groups", "Groups user belongs to.").DataType("array of string")))
	api.Route(api.GET("/user/{id}").Filter(checkAuthentication).Filter(checkAuthorization).To(fetchUser).
		Doc("Fetch information about a user.").
		Param(api.PathParameter("id", "Id of user to fetch").DataType("int")))
	api.Route(api.PUT("/user/{id}").Filter(checkAuthentication).Filter(checkAuthorization).To(modifyUser).
		Doc("Change attributes on a user.").
		Param(api.PathParameter("id", "Id of user to modify.").DataType("int")).
		Param(api.BodyParameter("name", "Name for user.").DataType("string")).
		Param(api.BodyParameter("groups", "Groups user belongs to.").DataType("array of int")))
	api.Route(api.DELETE("/user/{id}").Filter(checkAuthentication).Filter(checkAuthorization).To(removeUser).
		Doc("Remove a user.").
		Param(api.PathParameter("id", "Id of user to modify.").DataType("int")))

	api.Route(api.GET("/secrets").Filter(checkAuthentication).To(allSecrets).
		Doc("Return all secrets for a user"))
	/*
		http.HandleFunc("/api/login", as.Login)
		http.HandleFunc("/api/auth", as.Authenticate)
		http.HandleFunc("/api/valid", as.Valid)
		http.HandleFunc("/api/makeUser", us.MakeUser)
	*/

	api.Route(api.GET("/doc").
		Produces("text/plain").
		To(func(req *restful.Request, resp *restful.Response) {
		var tw *tabwriter.Writer = tabwriter.NewWriter(resp.ResponseWriter, 0, 8, 2, '\t', tabwriter.StripEscape)
		for _, r := range api.Routes() {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Path, r.Method, r.Doc)
			path := make([]string, 0)
			body := make([]string, 0)
			query := make([]string, 0)

			d := r.ParameterDocs
			for _, p := range d {
				d := p.Data()
				switch d.Kind {
				case restful.PATH_PARAMETER:
					path = append(path, fmt.Sprintf("* %s\t%s\t%s\n", d.Name, d.DataType, d.Description))
				case restful.BODY_PARAMETER:
					body = append(body, fmt.Sprintf("* %s\t%s\t%s\n", d.Name, d.DataType, d.Description))
				case restful.QUERY_PARAMETER:
					query = append(query, fmt.Sprintf("* %s\t%s\t%s\n", d.Name, d.DataType, d.Description))
				}
			}
			if len(path) > 0 {
				fmt.Fprintln(tw, "Path Parameters:")
				for _, v := range path {
					fmt.Fprint(tw, v)
				}
			}
			if len(body) > 0 {
				fmt.Fprintln(tw, "Body Parameters:")
				for _, v := range body {
					fmt.Fprint(tw, v)
				}
			}
			if len(query) > 0 {
				fmt.Fprintln(tw, "Query Parameters:")
				for _, v := range query {
					fmt.Fprint(tw, v)
				}
			}
			fmt.Fprintln(tw)
		}
		tw.Flush()
	}).
		Doc("Print automatic documentation."))

	restful.Add(ws)
	restful.Add(api)
	glog.Infof("Starting Server on %s:%d\n", bind, port)
	srv := &http.Server{Addr: fmt.Sprintf("%s:%d", bind, port), ReadTimeout: time.Duration(60) * time.Second, WriteTimeout: time.Duration(60) * time.Second}
	glog.Fatal(srv.ListenAndServe())
}
