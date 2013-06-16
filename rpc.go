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
	"fmt"
	"github.com/gorilla/rpc/v2/json2"
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

// TODO: validator service

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

type PingReply struct {
	Success bool
}

type PingService struct{}

func (p *PingService) Ping(req *http.Request, _, r *PingReply) error {
	r.Success = true
	return nil
}

type AuthService struct {
	DB           *sql.DB
	id           *sql.Stmt
	insChallenge *sql.Stmt
	insToken     *sql.Stmt
}

func (a *AuthService) getId(name string) (int64, error) {
	var id int64
	var err error
	if a.id == nil {
		a.id, err = a.DB.Prepare("SELECT id FROM users WHERE name = $1")
		if err != nil {
			l.Fatalf("Failed prpare for getId: %v", err)
		}
	}
	err = a.id.QueryRow(name).Scan(&id)
	if err != nil {
		return 0, &json2.Error{
			Code:    json2.E_BAD_PARAMS,
			Message: fmt.Sprintf("No such user '%s'", name),
			Data:    fmt.Sprintf("%v", err),
		}
	}
	return id, nil
}

func (a *AuthService) setChallenge(id int64, c []byte) error {
	var err error
	if a.insChallenge == nil {
		a.insChallenge, err = a.DB.Prepare("INSERT INTO session (id, challenge, expire) VALUES ($1, $2, $3);")
		if err != nil {
			l.Fatalf("Failed prpare for setChallenge: %v", err)
		}
	}
	_, err = a.insChallenge.Exec(id, c, time.Now().Add(time.Duration(challengeExpire)*time.Minute))
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthService) setToken(id int64, tok []byte) error {
	var err error
	if a.insToken == nil {
		a.insToken, err = a.DB.Prepare("INSERT INTO session (id, token, expire) VALUES ($1, $2, $3);")
		if err != nil {
			l.Fatalf("Failed prpare for setToken: %v", err)
		}
	}
	_, err = a.insToken.Exec(id, tok, time.Now().Add(time.Duration(tokenExpire)*time.Minute))
	if err != nil {
		return err
	}
	return nil
}

type AuthArgs struct {
	Name  string
	Token string
}

type AuthReply struct {
	Token string
}

func (a *AuthService) Login(req *http.Request, arg *AuthArgs, r *AuthReply) error {
	var der []byte
	id, err := a.getId(arg.Name)
	if err != nil {
		return err
	}
	l.Printf("Auth.Login: %s\n", arg.Name)
	err = a.DB.QueryRow("SELECT pubKey FROM users WHERE name=$1", arg.Name).Scan(&der)
	if err != nil {
		return err
	}
	c := make([]byte, challengeSize)
	_, err = io.ReadFull(rand.Reader, c)
	if err != nil {
		return err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}
	tok, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub.(*rsa.PublicKey), c, []byte(arg.Name))
	if err != nil {
		return err
	}
	r.Token = base64.StdEncoding.EncodeToString(tok)
	err = a.setChallenge(id, c)
	if err != nil {
		return err
	}
	l.Printf("Auth.Login: sent challenge for %s\n", arg.Name)
	return nil
}

func (a *AuthService) Authenticate(req *http.Request, arg *AuthArgs, r *AuthReply) error {
	var expire time.Time
	c := make([]byte, challengeSize)
	id, err := a.getId(arg.Name)
	if err != nil {
		return err
	}
	l.Printf("Auth.Authenticate: %s\n", arg.Name)
	err = a.DB.QueryRow("SELECT challenge, expire FROM session WHERE id=$1", id).Scan(&c, &expire)
	if err != nil {
		return err
	}
	if !bytes.Equal(c, decodeBase64(arg.Token)) || time.Since(expire).Minutes() > float64(challengeExpire) {
		l.Printf("Auth.Authenticate: denied for %s\n", arg.Name)
		return &json2.Error{
			Code:    json2.E_BAD_PARAMS,
			Message: "Token incorrect or expired",
		}
	}
	tok := make([]byte, tokenSize)
	_, err = io.ReadFull(rand.Reader, tok)
	if err != nil {
		return err
	}
	r.Token = base64.StdEncoding.EncodeToString(tok)
	err = a.setToken(id, tok)
	if err != nil {
		return err
	}
	l.Printf("Auth.Authenticate: sent token for %s\n", arg.Name)
	return nil
}
