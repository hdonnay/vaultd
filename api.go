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
	"github.com/golang/glog"
	//"crypto/x509"
	"database/sql"
	"encoding/base64"
	//"fmt"
	//"errors"
	"fmt"
	"io"
	"net/http"
	//"time"
	"regexp"
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
		if glog.V(2) {
			glog.Warningln("'Token' not set in cookie")
		}
		resp.WriteErrorString(400, "'Token' not set in cookie")
		return
	}
	idStr, err := req.Request.Cookie("Id")
	if err != nil {
		if glog.V(2) {
			glog.Warningln("'Id' not set in cookie")
		}
		resp.WriteErrorString(400, "'Id' not set in cookie")
		return
	}
	id, err = strconv.ParseInt(idStr.Value, 10, 64)
	if err != nil {
		if glog.V(2) {
			glog.Warningln("'Id' not valid int64")
		}
		resp.WriteErrorString(400, "'Id' not valid int64")
		return
	}
	err = q["checkToken"].QueryRow(id, decodeBase64(token.Value)).Scan(&valid)
	if err != nil {
		if glog.V(2) {
			glog.Errorf("Token checking SQL returned error: %v\n", q["checkToken"])
		}
		resp.WriteErrorString(500, "error checking token")
		return
	}
	if !valid {
		if glog.V(1) {
			glog.Infof("Auth BAD for %d\n", id)
		}
		resp.WriteErrorString(401, "Unauthenticated")
		return
	}
	if glog.V(1) {
		glog.Infof("Auth OK for %d\n", id)
	}
	chain.ProcessFilter(req, resp)
}

func checkAuthorization(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	idStr, _ := req.Request.Cookie("Id")
	id, _ := strconv.ParseInt(idStr.Value, 10, 64)
	u, _ := GetUser(id)
	if path, _ := regexp.MatchString("^/api/user(/.*)?$", req.Request.URL.Path); path {
		switch req.Request.Method {
		case "DELETE", "PUT":
			if !u.Admin || req.PathParameter("id") != string(u.Id) {
				resp.WriteErrorString(403, "Unauthorized")
				return
			}
		case "POST":
			if !u.Admin {
				resp.WriteErrorString(403, "Unauthorized")
				return
			}
		default:
			break
		}
	}
	chain.ProcessFilter(req, resp)
	return
}

// GET /api/auth?name=me
//     {"id": int, "challenge": <base64 string>}
func getChallenge(req *restful.Request, resp *restful.Response) {
	var err error
	var name string = req.PathParameter("name")
	var c []byte = make([]byte, challengeSize)

	u, err := GetUserByName(name)
	if err != nil {
		if glog.V(2) {
			glog.Errorln(err)
		}
		resp.WriteErrorString(http.StatusBadRequest, "Cannot find user")
		return
	}

	_, err = io.ReadFull(rand.Reader, c)
	if err != nil {
		glog.Errorln(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error generating challenge")
		return
	}

	//box, ok := box.SignAndSeal(c, boxPriv, boxPub, *u.PubKey)
	box, ok := box.Seal(c, u.PubKey)
	if !ok {
		glog.Errorln("Error boxing challenge")
		resp.WriteErrorString(http.StatusInternalServerError, "Error boxing challenge")
		return
	}
	err = SaveChallenge(u.Id, c)
	if err != nil {
		glog.Errorln(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error recording challenge")
		return
	}

	resp.WriteEntity(&map[string]string{"challenge": base64.StdEncoding.EncodeToString(box), "id": fmt.Sprintf("%d", u.Id)})
	if glog.V(1) {
		glog.Infof("Auth.Login: sent challenge for %s\n", name)
		if glog.V(3) {
			glog.Infof("id:\t%d\n", u.Id)
			glog.Infof("token:\t%x\n", c)
			glog.Infof("encrypted challenge:\t%v\n", base64.StdEncoding.EncodeToString(box))
		}
	}
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
		if glog.V(1) {
			glog.Warningln(err)
		}
		resp.WriteErrorString(http.StatusInternalServerError, "Error deserialzing response")
		return
	}

	if glog.V(3) {
		glog.Infof("recv'd:\t%+v\n", c)
	}
	_, okC := c["challenge"]
	_, okI := c["id"]
	if !(okC && okI) {
		if glog.V(2) {
			glog.Warningln("Malformed response")
		}
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
		glog.Errorln(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error generating token")
		return
	}

	err = SaveToken(id, tok)
	if err != nil {
		glog.Errorln(err)
		resp.WriteErrorString(http.StatusInternalServerError, "Error saving token")
		return
	}

	for k, v := range map[string]string{
		"Token": base64.StdEncoding.EncodeToString(tok),
		"Id":    fmt.Sprintf("%d", id),
	} {
		cookie := &http.Cookie{Name: k, Value: v}
		http.SetCookie(resp.ResponseWriter, cookie)
		if glog.V(3) {
			glog.Infof("Set cookie:\t%s:%s\n", k, v)
		}
	}
	if glog.V(3) {
		glog.Infof("Send auth token for %d\n", id)
	}

	return
}

func fetchUser(req *restful.Request, resp *restful.Response) {
	id, err := strconv.ParseInt(req.PathParameter("id"), 10, 64)
	if err != nil {
		if glog.V(2) {
			glog.Warningln("unable to parse id")
		}
		resp.WriteErrorString(http.StatusBadRequest, "unable to parse Id")
		return
	}
	u, err := GetUser(id)
	if err != nil {
		if glog.V(2) {
			glog.Warningf("unable to find user with id %d\n", id)
		}
		resp.WriteErrorString(http.StatusBadRequest, "unable to find user with Id")
		return
	}
	if glog.V(3) {
		glog.Infof("Sent info for user %d\n", id)
	}
	resp.WriteEntity(u)
}

func createUser(req *restful.Request, resp *restful.Response) {
	var err error
	var body struct {
		Admin  bool
		Name   string
		Groups []int64
	}

	err = req.ReadEntity(&body)
	if err != nil {
		glog.Info("Malformed body")
		resp.WriteErrorString(http.StatusBadRequest, "malformed body")
		return
	}
	if glog.V(3) {
		glog.Info(body)
	}
}

func modifyUser(req *restful.Request, resp *restful.Response) {
	id, err := strconv.ParseInt(req.PathParameter("id"), 10, 64)
	if err != nil {
		if glog.V(2) {
			glog.Warningln("unable to parse id")
		}
		resp.WriteErrorString(http.StatusBadRequest, "unable to parse Id")
		return
	}
	resp.WriteErrorString(http.StatusNotImplemented, fmt.Sprintf("%d", id))
	return
}

func removeUser(req *restful.Request, resp *restful.Response) {
	id, err := strconv.ParseInt(req.PathParameter("id"), 10, 64)
	if err != nil {
		if glog.V(2) {
			glog.Warningln("unable to parse id")
		}
		resp.WriteErrorString(http.StatusBadRequest, "unable to parse Id")
		return
	}
	resp.WriteErrorString(http.StatusNotImplemented, fmt.Sprintf("%d", id))
	return
}

func searchUser(req *restful.Request, resp *restful.Response) {
	var name string = req.QueryParameter("name")
	var id []int64
	rows, err := db.Query("SELECT id FROM users WHERE name LIKE $1;", name)
	if err != nil {
		glog.Error(err)
		return
	}

	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err != nil {
			glog.Error(err)
			return
		}
		id = append(id, t)
	}

	if len(id) == 0 {
		if glog.V(2) {
			glog.Infof("bad name: %s\n", name)
		}
		resp.WriteErrorString(http.StatusBadRequest, "unable to find any user with name")
		return
	}
	if glog.V(3) {
		glog.Infof("Successful search for user %d\n", id)
	}
	resp.WriteEntity(&map[string][]int64{"id": id})
}

func allSecrets(req *restful.Request, resp *restful.Response) {
	var rows *sql.Rows
	type row struct {
		Id       int64
		Revision int64
		URI      string
		Note     string
		Secret   []byte
		SignerId int64
	}
	var ret []row //= make(row, 0)
	idStr, _ := req.Request.Cookie("Id")
	id, _ := strconv.ParseInt(idStr.Value, 10, 64)
	rows, err := db.Query("SELECT (id, rev, uri, note, box, signer) FROM users_secrets WHERE uid = $1;", id)
	if err != nil {
		glog.Error(err)
		resp.WriteErrorString(500, "Problem querying database")
	}

	for rows.Next() {
		var id, rev, signerId int64
		var uri, note string
		var secret []byte
		rows.Scan(&id, &rev, &uri, &note, &secret, &signerId)
		ret = append(ret, row{id, rev, uri, note, secret, signerId})
	}
	resp.WriteEntity(&map[string][]row{"secrets": ret})
}
