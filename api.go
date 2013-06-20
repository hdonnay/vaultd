// Clients are expected to attempt a handshake if they receive a 401
package main

// vim: set noexpandtab :

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	//"fmt"
	"errors"
	"io"
	"net/http"
	"time"
)

const (
	challengeSize   int = 16 // bytes
	challengeExpire int = 2  //minutes
	tokenSize       int = 16 // bytes
	tokenExpire     int = 5  //minutes
)

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

// Validation bits: Make it so we can call .validate() on all our
// "service" structs
type validateRequest struct {
	Token []byte
	Id    int64
	Reply chan bool
}

type ValidateService struct {
	validateChan chan *validateRequest
}

func (v *ValidateService) validate(id int64, token []byte) bool {
	reply := make(chan bool)
	defer close(reply)
	v.validateChan <- &validateRequest{Id: id, Token: token, Reply: reply}
	return <-reply
}

// make a struct so we're not free-forming errors all over.
type JsonError struct {
	Success bool
	Message string
}

// AuthService abuses the fact that postgres' temp tables are per-session to
// implement some session state. All tokens/challenges will be lost and have to
// be re-negotianted if the daemon comes down and up.
type AuthService struct {
	ValidateService
	db           *sql.DB
	selId        *sql.Stmt
	insChallenge *sql.Stmt
}

func (a *AuthService) getId(name string) (int64, error) {
	var id int64
	err := a.selId.QueryRow(name).Scan(&id)
	if err != nil {
		return 0, errors.New("No such user")
	}
	return id, nil
}

func (a *AuthService) setChallenge(id int64, c []byte) error {
	var err error
	_, err = a.db.Exec("DELETE FROM session WHERE id = $1 AND token IS NULL;", id)
	if err != nil {
		return err
	}
	_, err = a.insChallenge.Exec(id, c, time.Now().Add(time.Duration(challengeExpire)*time.Minute))
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthService) setToken(id int64, tok []byte) error {
	tx, err := a.db.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("DELETE FROM session WHERE id = $1 AND challenge IS NULL;", id)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("INSERT INTO session (id, token, expire) VALUES ($1, $2, $3);",
		id, tok, time.Now().Add(time.Duration(tokenExpire)*time.Minute))
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return err
	}
	return nil
}

// Argument:
//     { "name": "user" }
//
// Response:
//     { "challenge": "base64String"}
func (a *AuthService) Login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var der []byte
	var arg struct{ Name string }
	if err := decoder.Decode(&arg); err != nil {
		l.Panic(err)
	}
	id, err := a.getId(arg.Name)
	if err != nil {
	}
	err = a.db.QueryRow("SELECT pubKey FROM users WHERE name=$1", arg.Name).Scan(&der)
	if err != nil {
		l.Panic(err)
	}
	c := make([]byte, challengeSize)
	_, err = io.ReadFull(rand.Reader, c)
	if err != nil {
		l.Panic(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		l.Panic(err)
	}
	tok, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub.(*rsa.PublicKey), c, []byte(arg.Name))
	if err != nil {
		l.Panic(err)
	}
	err = a.setChallenge(id, c)
	if err != nil {
		l.Panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(&map[string]string{"challenge": base64.StdEncoding.EncodeToString(tok)})
	w.Write(res)
	l.Printf("Auth.Login: sent challenge for %s\n", arg.Name)
}

// Argument:
//     { "name": "user", "token": "base64String" }
//
// Response:
//     { "token": "base64String" }
//   or
//     401 Unauthorized
func (a *AuthService) Authenticate(w http.ResponseWriter, r *http.Request) {
	var arg struct {
		Name  string
		Token string
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&arg); err != nil {
		l.Panic(err)
	}
	id, err := a.getId(arg.Name)
	if err != nil {
		l.Panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	rows, err := a.db.Query("SELECT challenge, expire FROM session WHERE id=$1", id)
	if err != nil {
		l.Panic(err)
	}
	for rows.Next() {
		var expire time.Time
		c := make([]byte, challengeSize)
		rows.Scan(&c, &expire)
		a.db.Exec("DELETE FROM session WHERE challenge = $1", c)
		if time.Since(expire).Minutes() <= float64(challengeExpire) && bytes.Equal(c, decodeBase64(arg.Token)) {
			tok := make([]byte, tokenSize)
			_, err = io.ReadFull(rand.Reader, tok)
			if err != nil {
				l.Panic(err)
			}
			err = a.setToken(id, tok)
			if err != nil {
				l.Panic(err)
			}
			res, _ := json.Marshal(&map[string]string{"token": base64.StdEncoding.EncodeToString(tok)})
			w.Write(res)
			l.Printf("Auth.Authenticate: sent token for %s\n", arg.Name)
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// Argument:
//     { "name": "user", "token": "base64String" }
//
// Response:
//     200 OK
//   or
//     401 Unauthorized
func (a *AuthService) Valid(w http.ResponseWriter, r *http.Request) {
	var arg struct {
		Name  string
		Token string
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&arg); err != nil {
		l.Println(err)
		return
	}
	id, err := a.getId(arg.Name)
	if err != nil {
		l.Println(err)
		return
	}
	if a.validate(id, decodeBase64(arg.Token)) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
