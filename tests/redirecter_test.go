package tests

import (
	"fmt"
	"github.com/yanatan16/goauth2"
	"github.com/yanatan16/goauth2/authcache"
	"github.com/yanatan16/goauth2/authhandler"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
)

const (
	auth_port_2     int = 15699
	redirecter_port int = 15696
)

var (
	auth_url_2     string
	redirecter_url string
	rreqs          chan *http.Request
)

func init() {
	redirecter_url = fmt.Sprintf("http://%s:%d", "127.0.0.1", redirecter_port)
	auth_url_2 = fmt.Sprintf("http://%s:%d/authorize", "127.0.0.1", auth_port_2)
	go ExampleRunGoauth2ServerWithRedirecter(auth_port_2, redirecter_url)

	rreqs = make(chan *http.Request, 5)
	httpd := &http.Server{
		Addr:           fmt.Sprintf(":%d", redirecter_port),
		Handler:        http.HandlerFunc(MyRedirecter),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start the server
	go func() {
		log.Fatal(httpd.ListenAndServe())
	}()
}

// Example way to run an goauth2 server
func ExampleRunGoauth2ServerWithRedirecter(port int, redirectUrl string) {
	// Create your implementations of AuthCache
	ac := authcache.NewBasicAuthCache()

	// Create your implementation of AuthHandler
	auth, err := authhandler.NewRedirecter(redirectUrl, redirectUrl)
	if err != nil {
		log.Fatal("Error intializing Redirecter", err)
	}

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

func MyRedirecter(w http.ResponseWriter, r *http.Request) {
	rreqs <- r
	w.Write([]byte("A-OK"))
}

func TestRedirecterImplicit(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "token", // This means use implicit auth grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "implicit_grant_test", // Prevent's cross-site scripting
	}

	response, err := http.Get(MakeQuery(querymap, auth_url_2))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response.Body.Close()

	// Make sure it went to our redirecter
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal("Error reading http response.", err)
	}
	if string(body) != "A-OK" {
		t.Error("Body of response did not match expected!", body)
	}

	select {
	case req := <-rreqs:
		// Check req has all the query parameters
		q := req.URL.Query()
		for k, v := range querymap {
			if q.Get(k) != v {
				t.Error("Request Query did not contain correct", k, q.Get(k))
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive redirect request!")
	}
}

func TestRedirecter(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "code", // This means use implicit auth grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "authcode_grant_test", // Prevent's cross-site scripting
	}

	response, err := http.Get(MakeQuery(querymap, auth_url_2))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response.Body.Close()

	// Make sure it went to our redirecter
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal("Error reading http response.", err)
	}
	if string(body) != "A-OK" {
		t.Error("Body of response did not match expected!", body)
	}

	select {
	case req := <-rreqs:
		// Check req has all the query parameters
		q := req.URL.Query()
		for k, v := range querymap {
			if q.Get(k) != v {
				t.Error("Request Query did not contain correct", k, q.Get(k))
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive redirect request!")
	}
}
