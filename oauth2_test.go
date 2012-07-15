package goauth2

import (
	"./authcache"
	"./clientstore"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const (
	auth_port int = 15697
	my_port   int = 15698
)

var (
	auth_url, api_url string
	redirect_url      string
	redirect_reqs     chan *http.Request
)

// Example way to run an goauth2 server
func ExampleRunGoauth2Server() {
	// Create your implementations of AuthCache and ClientStore
	ac := authcache.NewBasicAuthCache()
	cs := clientstore.NewBasicClientStore()

	// This initialization is for testing only
	cs.AddClient("client1")
	cs.AddClient("client2")
	cs.AddClient("client3")

	// Create the store and the server
	store := NewStore(cs, ac)
	server := NewServer(store, AuthHandler(authCodeAuthHandler), AuthHandler(implicitAuthHandler))

	// Create the Serve Mux for http serving
	sm := http.NewServeMux()
	sm.Handle("/authorize", http.HandlerFunc(server.MasterHandler))

	// You might have multiple uses, each should be wrapped using TokenVerifier
	sm.Handle("/api", TokenVerifier(http.HandlerFunc(apiHandler)))

	// Create the http server
	httpd := &http.Server{
		Addr:           auth_port,
		Handler:        sm,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start the server
	log.Fatal(httpd.ListenAndServe())
}

func implicitAuthHandler(w http.ResponseWriter, r *http.Request, oar OAuthRequest) {
	// Respond favorably to client1, fail on rest
	if oar.ClientID == "client1" {
		oar.ImplicitRedirect(w, r, nil)
	} else {
		err := NewServerError(ErrorCodeAccessDenied, "access denied", "")
		oar.ImplicitRedirect(w, r, error)
	}
}

func authCodeAuthHandler(w http.ResponseWriter, r *http.Request, oar OAuthRequest) {
	// Respond favorably to client1, fail on rest
	if oar.ClientID == "client1" {
		oar.AuthCodeRedirect(w, r, nil)
	} else {
		err := NewServerError(ErrorCodeAccessDenied, "access denied", "")
		oar.AuthCodeRedirect(w, r, error)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func init() {
	go ExampleRunGoauth2Server()
	api_url = fmt.Sprintf("http://%s:%d/api", "127.0.0.1", auth_port)
	auth_url = fmt.Sprintf("http://%s:%d/authorize", "127.0.0.1", auth_port)
	redirect_url = fmt.Sprintf("http://%s:%d/redirect", "127.0.0.1", my_port)

	redirect_reqs = make(chan *http.Request, 25)
	http.Handle("/redirect", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			redirect_reqs <- r
			w.Write([]byte("Redirect"))
		}))

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", my_port)))
	}()
}

func makeQuery(query map[string]string, base_url string) string {
	if len(query) == 0 {
		return base_url
	}
	str := []byte(base_url + "?")
	for k, v := range query {
		str = append(str, url.QueryEscape(k)+"=")
		str = append(str, url.QueryEscape(v)+"&")
	}
	str = str[:len(str)-1] // Cut off last &
	return string(str)
}

func ApiUseTest(t *testing.T, token string) {
	req, err := http.Get("GET", api_url, nil)
	if err != nil {
		t.Fatal("Error creating API Use Request", err)
	}

	req.Header.Add("Authorization", token)

	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
	}

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

	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "token", // This means use implicit auth grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "implicit_grant_test", // Prevent's cross-site scripting
	}

	response, err := http.Get(makeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	response.Body.Close()

	// Now look at redirect request
	var token string
	select {
	case req := <-redirect_reqs:
		frag := url.ParseQuery(req.URL.Fragment) // Parse query as fragment
		if errstr := frag.Get("error"); errstr != "" {
			t.Fatal("Request Fragment contained error",
				frag.Get("error"), frag.Get("error_description"),
				frag.Get("error_uri"))
		} else if ttype := frag.Get("token_type"); ttype != "bearer" || ttype != "mac" {
			t.Fatal("Request fragment contained bad token_type", ttype)
		} else if expiry := strconv.ParseInt(frag.Get("expires_in"), 10, 32); expiry != authcache.TokenExpiry {
			t.Fatal("Request fragment contained bad expires_in", expiry)
		} else if state := frag.Get("state"); state != "implicit_grant_test" {
			t.Fatal("Request fragment contained bad state", state)
		}
		token = frag.Get("token")
	case <-time.After(2 * time.Second):
		t.Fatal("Request not received in time.")
	}

	// Test using the access token
	ApiUseTest(t, token)
}

// Test the authorization code grant flow of OAuth 2.0
func TestAuthCodeGrant(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "code", // This means use auth code grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "authcode_grant_test", // Prevent's cross-site scripting
	}

	response, err := http.Get(makeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	response.Body.Close()

	// Now look at redirect request
	var code string
	select {
	case req := <-redirect_reqs:
		q := req.URL.Parse() // Parse query
		if errstr := q.Get("error"); errstr != "" {
			t.Fatal("Request Fragment contained error",
				q.Get("error"), q.Get("error_description"),
				q.Get("error_uri"))
		}
		code = q.Get("code")
	case <-time.After(2 * time.Second):
		t.Fatal("Request not received in time.")
	}

	// Perform the Access requet
	querymap = map[string]string{
		"grant_type":   "authorization_code", // This means use auth code grant
		"redirect_uri": redirect_url,
		"code":         code,
	}

	response2, err := http.Get(makeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response2.Body.Close()

	// Check Response
	if response2.StatusCode != 200 {
		t.Error("Response Status is not 200!", response2.Status)
	}
	body, err = ioutil.ReadAll(response2.Body)
	if err != nil {
		t.Fatal("Couldn't read response body.", err)
	}

	ret := make(map[string]string)
	err = json.Unmarshal(body, ret)
	if err != nil {
		t.Fatal("Could not unmarshal response body.", err)
	}

	err, ok := ret["error"]
	if ok {
		t.Fatal("Error in response body:", err,
			ret["error_description"], ret["error_uri"])
	}

	token, ok := ret["token"]
	if !ok {
		t.Fatal("Token not included in response!", body)
	}

	ttype, ok := ret["token_type"]
	if !ok {
		t.Fatal("Token Type not included in response!", body)
	} else if ttype != "bearer" || ttype != "mac" {
		t.Fatal("Token Type is not valid", ttype)
	}

	expiry_str, ok := ret["expires_in"]
	if !ok {
		t.Fatal("Expires Time not included in response", body)
	} else if expiry := strconv.ParseInt(expiry_str, 10, 32); expiry != authcache.TokenExpiry {
		t.Fatal("Expires In Time not consistent.", expiry)
	}

	ApiUseTest(t, token)
}
