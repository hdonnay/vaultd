// Clients are expected to attempt a handshake if they receive HTTP 401
//
//
// Any method may return HTTP 500
package main

// vim: set noexpandtab:

import (
	//"bytes"
	"crypto/rand"
	"github.com/emicklei/go-restful"
	"github.com/gokyle/cryptobox/box"
	//"crypto/x509"
	//	"database/sql"
	"encoding/base64"
	//"fmt"
	//"errors"
	"fmt"
	"io"
	"net/http"
	//"time"
	"strconv"
)

const (
	challengeSize int = 16 // bytes
	tokenSize     int = 32 // bytes
)

func checkAuthentication(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	var err error
	var token *http.Cookie
	var id int64
	var valid bool
	token, err = req.Request.Cookie("Token")
	if err != nil {
		resp.WriteErrorString(400, "'Token' not set in cookie")
		l.Println("'Token' not set in cookie")
		return
	}
	idStr, err := req.Request.Cookie("Id")
	if err != nil {
		resp.WriteErrorString(400, "'Id' not set in cookie")
		l.Println("'Id' not set in cookie")
		return
	}
	id, err = strconv.ParseInt(idStr.Value, 10, 64)
	if err != nil {
		resp.WriteErrorString(400, "'Id' not valid int64")
		l.Println("'Id' not valid int64")
		return
	}
	err = q["checkToken"].QueryRow(id, decodeBase64(token.Value)).Scan(&valid)
	if err != nil {
		resp.WriteErrorString(500, "error checking token")
		l.Printf("Token checking SQL returned error: %v\n", q["checkToken"])
		return
	}
	if !valid {
		resp.WriteErrorString(401, "Unauthenticated")
		l.Printf("Auth BAD for %d\n", id)
		return
	}
	l.Printf("Auth OK for %d\n", id)
	chain.ProcessFilter(req, resp)
}

func checkAuthorization(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	chain.ProcessFilter(req, resp)
}

// GET /api/auth?name=me
//     {"id": int, "challenge": <base64 string>}
func getChallenge(req *restful.Request, resp *restful.Response) {
	var err error
	var name string = req.PathParameter("name")
	var c []byte = make([]byte, challengeSize)

	u, err := GetUserByName(name)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusBadRequest, "Cannot find user")
		return
	}

	_, err = io.ReadFull(rand.Reader, c)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error generating challenge")
		return
	}

	//box, ok := box.SignAndSeal(c, boxPriv, boxPub, *u.PubKey)
	box, ok := box.Seal(c, *u.PubKey)
	if !ok {
		l.Println("Error boxing challenge")
		resp.WriteErrorString(http.StatusInternalServerError, "Error boxing challenge")
		return
	}
	err = SaveChallenge(u.Id, c)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error recording challenge")
		return
	}

	resp.WriteEntity(&map[string]string{"challenge": base64.StdEncoding.EncodeToString(box), "id": fmt.Sprintf("%d",u.Id)})
	l.Printf("Auth.Login: sent challenge for %s\n", name)
	l.Printf("token:\t%x\n", c)
	l.Printf("encrypted challenge:\t%v\n", base64.StdEncoding.EncodeToString(box))
	l.Printf("id:\t%d\n", u.Id)
	return
}

// POST /api/auth {"id": <int>, "challenge": <base64 string>}
//      <Cookies>
func postChallenge(req *restful.Request, resp *restful.Response) {
	var err error
	var tok []byte = make([]byte, tokenSize)
	var c map[string]string

	err = req.ReadEntity(&c)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error deserialzing response")
		return
	}

	l.Printf("got: %+v\n", c)
	_, okC := c["challenge"]
	_, okI := c["id"]
	if !(okC && okI) {
		l.Println("Malformed response")
		resp.WriteErrorString(http.StatusBadRequest, "Malformed response")
		return
	}

	id, err := strconv.ParseInt(c["id"], 10, 64)
	if err != nil {
		resp.WriteErrorString(http.StatusBadRequest, "Invalid Credentials")
		return
	}

	if !CheckChallenge(id, decodeBase64(c["challenge"])) {
		resp.WriteErrorString(http.StatusBadRequest, "Invalid Credentials")
		return
	}

	_, err = io.ReadFull(rand.Reader, tok)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error generating token")
		return
	}

	err = SaveToken(id, tok)
	if err != nil {
		l.Println(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error saving token")
		return
	}

	for k, v :=  range map[string]string{
		"Token": base64.StdEncoding.EncodeToString(tok),
		"Id": fmt.Sprintf("%d", id),
	} {
		cookie := &http.Cookie{ Name: k, Value: v}
		http.SetCookie(resp.ResponseWriter, cookie)
	}

	return
}
