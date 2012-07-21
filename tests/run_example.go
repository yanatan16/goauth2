// This package provides a few ways to test a server implementing goauth2
// with their specific AuthCache implementation
package tests

import (
	"fmt"
	"github.com/yanatan16/goauth2"
	"github.com/yanatan16/goauth2/authcache"
	"github.com/yanatan16/goauth2/authhandler"
	"log"
	"net/http"
	"time"
)

// Example way to run an goauth2 server
func ExampleRunGoauth2Server(port int) {
	// Create your implementations of AuthCache
	ac := authcache.NewBasicAuthCache()

	// Create your implementation of AuthHandler
	auth := authhandler.NewWhiteList("client1")

	// Create the store and the server
	server := goauth2.NewServer(ac, auth)

	// Create the Serve Mux for http serving
	sm := http.NewServeMux()
	sm.Handle("/authorize", server.MasterHandler())

	// You might have multiple uses, each should be wrapped using TokenVerifier
	sm.Handle("/api", server.TokenVerifier(http.HandlerFunc(TestApiHandler)))

	// Create the http server
	httpd := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        sm,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start the server
	log.Fatal(httpd.ListenAndServe())
}

func TestApiHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Recieved Request for API")
	w.Write([]byte("OK"))
}
