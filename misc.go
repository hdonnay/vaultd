package main

// vim: set noexpandtab :

import (
	"net/http"
	"strconv"
	//"database/sql"
	"errors"
	"encoding/base64"
	//"os"
	//"time"
)

func nextId(table string) (int64, error) {
	var id int64
	switch table {
	case "group":
		db.QueryRow("SELECT max(id) FROM groups;").Scan(&id)
	case "user":
		db.QueryRow("SELECT max(id) FROM users;").Scan(&id)
	case "secret":
		db.QueryRow("SELECT max(id) FROM secrets;").Scan(&id)
	default:
		return -1, errors.New("bad table")
	}
	return (id + 1), nil
}

func decodeBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		return nil
	}
	return out[0:n]
}

func parseCookie(r *http.Request) (id int64, tok string) {
	var c *http.Cookie
	var err error
	if c, err = r.Cookie("id"); err != nil {
		l.Println(err)
		return -1, ""
	}
	id, _ = strconv.ParseInt(c.Value, 10, 64)
	if c, err = r.Cookie("token"); err != nil {
		l.Println(err)
		return -1, ""
	}
	tok = c.Value
	return
}
