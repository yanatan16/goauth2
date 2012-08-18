package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

const my_port int = 15698

var (
	auth_url      string
	redirect_url  string
	redirect_reqs chan *http.Request
	fragments     chan string
)

// An ApiCheck function is meant to lightly access the API using
// a verified uri with the token to make sure token verification works
type ApiCheck func(t *testing.T, token string)

func InitTests(myaddr, authUrl string) {
	auth_url = authUrl
	redirect_url = fmt.Sprintf("http://%s:%d/redirect", myaddr, my_port)

	redirect_reqs = make(chan *http.Request, 25)
	fragments = make(chan string, 10)

	http.Handle("/redirect", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log.Println("Received Request for Redirect Return")
			redirect_reqs <- r
			w.Write([]byte("Redirect"))
		}))

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", myaddr, my_port), nil))
	}()

	// Make sure to wait for the http servers
	<-time.After(time.Second / 2)
}

func MakeQuery(query map[string]string, base_url string) string {
	if len(query) == 0 {
		return base_url
	}
	uri := base_url + "?"
	for k, v := range query {
		uri += url.QueryEscape(k) + "=" + url.QueryEscape(v) + "&"
	}
	uri = uri[:len(uri)-1] // Cut off last &
	return string(uri)
}

func FragmentStrippingRedirector(new *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	// Strip fragment
	if len(new.URL.Fragment) > 0 {
		fragments <- new.URL.Fragment
	}
	return nil
}

// Test the implicit grant flow of OAuth 2.0
func DoTestImplicitGrant(t *testing.T, checkApi ApiCheck) (token string) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "token", // This means use implicit auth grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "implicit_grant_test", // Prevent's cross-site scripting
	}

	client := &http.Client{
		CheckRedirect: FragmentStrippingRedirector,
	}

	response, err := client.Get(MakeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response.Body.Close()

	if response.Header.Get("Content-Type") == "application/json" {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatal("Couldn't read response body.", err)
		}

		ret := make(map[string]string)
		err = json.Unmarshal(body, &ret)
		if err != nil {
			t.Fatal("Could not unmarshal response body.", err)
		}

		if errstr, ok := ret["error"]; ok {
			t.Fatal("Error on initial authorization query", errstr,
				ret["error_description"], ret["error_uri"])
		}
	}

	// Now look at redirect request
	select {
	case fragstr := <-fragments:
		frag, err := url.ParseQuery(fragstr)
		if err != nil {
			t.Fatal("Error parsing URL Fragment", fragstr)
		}
		if errstr := frag.Get("error"); errstr != "" {
			t.Fatal("Request Fragment contained error",
				frag.Get("error"), frag.Get("error_description"),
				frag.Get("error_uri"))
		}
		if ttype := frag.Get("token_type"); !(ttype == "bearer" || ttype == "mac") {
			t.Fatalf("Request fragment contained bad token_type: %s / %s", ttype, fragstr)
		}
		exp := frag.Get("expires_in")
		if exp != "" {
			if _, err := strconv.ParseInt(exp, 10, 64); err != nil {
				t.Fatal("Error parsing expires_in value into int", err)
			}
		}
		if state := frag.Get("state"); state != "implicit_grant_test" {
			t.Fatal("Request fragment contained bad state", state)
		}
		token = frag.Get("token")
	case <-time.After(2 * time.Second):
		t.Fatal("Fragment not received in time.")
	}

	// Clear Redirects
	select {
	case <-redirect_reqs:
	case <-time.After(time.Second):
	}

	// Test using the access token
	if checkApi != nil {
		checkApi(t, token)
	}

	return token
}

// Test the authorization code grant flow of OAuth 2.0
func DoTestAuthCodeGrant(t *testing.T, checkApi ApiCheck) (token string) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "code", // This means use auth code grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "authcode_grant_test", // Prevent's cross-site scripting
	}

	response, err := http.Get(MakeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response.Body.Close()

	if response.Header.Get("Content-Type") == "application/json" {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatal("Couldn't read response body.", err)
		}

		ret := make(map[string]string)
		err = json.Unmarshal(body, &ret)
		if err != nil {
			t.Fatal("Could not unmarshal response body.", err)
		}

		if errstr, ok := ret["error"]; ok {
			t.Fatal("Error on initial authorization query", errstr,
				ret["error_description"], ret["error_uri"])
		}
	}

	// Now look at redirect request
	var code string
	select {
	case req := <-redirect_reqs:
		q := req.URL.Query() // Parse query
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

	response2, err := http.Get(MakeQuery(querymap, auth_url))
	if err != nil {
		t.Fatal("Error on http.Get", err)
	}
	defer response2.Body.Close()

	// Check Response
	if response2.StatusCode != 200 {
		t.Error("Response Status is not 200!", response2.Status)
	}
	body, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		t.Fatal("Couldn't read response body.", err)
	}

	ret := make(map[string]string)
	err = json.Unmarshal(body, &ret)
	if err != nil {
		t.Fatal("Could not unmarshal response body.", err)
	}

	errstr, ok := ret["error"]
	if ok {
		t.Fatal("Error in response body:", errstr,
			ret["error_description"], ret["error_uri"])
	}

	token, ok = ret["token"]
	if !ok {
		t.Fatal("Token not included in response!", body)
	}

	ttype, ok := ret["token_type"]
	if !ok {
		t.Fatal("Token Type not included in response!", body)
	} else if ttype != "bearer" && ttype != "mac" {
		t.Fatal("Token Type is not valid", ttype)
	}

	expiry_str, ok := ret["expires_in"]
	if ok {
		if _, err := strconv.ParseInt(expiry_str, 10, 64); err != nil {
			t.Fatal("Expires Time could not be parsed into an int", err)
		}
	}

	// Test using the access token
	if checkApi != nil {
		checkApi(t, token)
	}

	return token
}
