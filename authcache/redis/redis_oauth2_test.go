package redis

import (
	. "./../../"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
)

const (
	auth_port   int    = 15697
	redis_addr  string = "tcp:127.0.0.1:6379"
	redis_dbnum int    = 0
	redis_pass  string = ""
)

var (
	api_url string
)

// Example way to run an goauth2 server
func ExampleRunGoauth2ServerWithRedis(port int) {
	// Create your implementations of AuthCache
	ac := NewRedisAuthCache(redis_addr, redis_dbnum, redis_pass)

	// Create your implementation of AuthHandler
	auth := TestAuthImpl(true)

	// Create the store and the server
	server := NewServer(ac, auth)

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

func init() {
	go ExampleRunGoauth2ServerWithRedis(auth_port)
	InitTests("127.0.0.1",
		fmt.Sprintf("http://%s:%d/authorize", "127.0.0.1", auth_port))

	api_url = fmt.Sprintf("http://%s:%d/api", "127.0.0.1", auth_port)
}

func apiUseTest(t *testing.T, token string) {
	req, err := http.NewRequest("GET", api_url, nil)
	if err != nil {
		t.Fatal("Error creating API Use Request", err)
	}

	req.Header.Add("Authorization", token)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Error making GET request for API with authorization", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatal("API Response Status code is bad", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("API response body could not be read", err)
	}
	if string(body) != "OK" {
		t.Error("API Response body is bad", body)
	}
}

// Test the implicit grant flow of OAuth 2.0
func TestImplicitGrant(t *testing.T) {
	DoTestImplicitGrant(t, ApiCheck(apiUseTest))
}

// Test the authorization code grant flow of OAuth 2.0
func TestAuthCodeGrant(t *testing.T) {
	DoTestAuthCodeGrant(t, ApiCheck(apiUseTest))
}

// Use a bad token to try and access the api
func TestBadTokenUse(t *testing.T) {
	token := "avpneqp984hrlkfzd"

	req, err := http.NewRequest("GET", api_url, nil)
	if err != nil {
		t.Fatal("Error creating API Use Request", err)
	}

	req.Header.Add("Authorization", token)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Error making GET request for API with authorization", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatal("API Response Status code is not unauthorized! ", resp.Status)
	}
}

// Test what happend when an auth code request fails
func TestFailedAuthCodeRequest(t *testing.T) {
	DoTestFailedAuthCodeRequest(t)
}

func TestFailedImplicitGrant(t *testing.T) {
	DoTestFailedImplicitGrant(t)
}
