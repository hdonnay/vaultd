package main

// vim: set noexpandtab :

import (
	"fmt"
	"html"
	"net/http"
)

func RootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q\n", html.EscapeString(r.URL.Path))
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "")
}
