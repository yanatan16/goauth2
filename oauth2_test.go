package goauth2

import (
	"./authcache"
   "errors"
   "strconv"
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
   fragments          chan string
)

// Example way to run an goauth2 server
func ExampleRunGoauth2Server() {
	// Create your implementations of AuthCache
	ac := authcache.NewBasicAuthCache()

   // Create your implementation of AuthHandler
   auth := authImpl(true)

	// Create the store and the server
	server := NewServer(ac, auth)

	// Create the Serve Mux for http serving
	sm := http.NewServeMux()
	sm.Handle("/authorize", server.MasterHandler())

	// You might have multiple uses, each should be wrapped using TokenVerifier
	sm.Handle("/api", server.TokenVerifier(http.HandlerFunc(apiHandler)))

	// Create the http server
	httpd := &http.Server{
		Addr:           fmt.Sprintf(":%d",auth_port),
		Handler:        sm,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start the server
	log.Fatal(httpd.ListenAndServe())
}

type authImpl bool

func (a authImpl) AuthorizeImplicit(w http.ResponseWriter, r *http.Request, oar *OAuthRequest) {
	// Respond favorably to client1, fail on rest
	if oar.ClientID == "client1" {
		oar.ImplicitRedirect(w, r, nil)
	} else {
		err := NewServerError(ErrorCodeAccessDenied, "access denied", "")
		oar.ImplicitRedirect(w, r, err)
	}
}

func (a authImpl) Authorize(w http.ResponseWriter, r *http.Request, oar *OAuthRequest) {
	// Respond favorably to client1, fail on rest
	if oar.ClientID == "client1" {
		oar.AuthCodeRedirect(w, r, nil)
	} else {
		err := NewServerError(ErrorCodeAccessDenied, "access denied", "")
		oar.AuthCodeRedirect(w, r, err)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
   log.Println("Recieved Request for API")
	w.Write([]byte("OK"))
}

func init() {
	go ExampleRunGoauth2Server()
	api_url = fmt.Sprintf("http://%s:%d/api", "127.0.0.1", auth_port)
	auth_url = fmt.Sprintf("http://%s:%d/authorize", "127.0.0.1", auth_port)
	redirect_url = fmt.Sprintf("http://%s:%d/redirect", "127.0.0.1", my_port)

	redirect_reqs = make(chan *http.Request, 25)
   fragments = make(chan string, 10)

	http.Handle("/redirect", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
         log.Println("Received Request for Redirect Return")
			redirect_reqs <- r
			w.Write([]byte("Redirect"))
		}))

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", my_port), nil))
	}()

   // Make sure to wait for the http servers
   <- time.After(time.Second / 2)
}

func makeQuery(query map[string]string, base_url string) string {
	if len(query) == 0 {
		return base_url
	}
	uri := base_url + "?"
	for k, v := range query {
		uri += url.QueryEscape(k)+"="+url.QueryEscape(v)+"&"
	}
	uri = uri[:len(uri)-1] // Cut off last &
	return string(uri)
}

func fragmentStrippingRedirector(new *http.Request, via []*http.Request) error {
   if len(via) >= 10 {
      return errors.New("stopped after 10 redirects")
   }
   // Strip fragment
   if len(new.URL.Fragment) > 0 {
      fragments <- new.URL.Fragment
   }
   return nil
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

	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "token", // This means use implicit auth grant
		"redirect_uri":  redirect_url,
		"scope":         "",                    // Not implemented right now
		"state":         "implicit_grant_test", // Prevent's cross-site scripting
	}

   client := &http.Client{
      CheckRedirect: fragmentStrippingRedirector,
   }

	response, err := client.Get(makeQuery(querymap, auth_url))
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
	var token string
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
      if expiry, err := strconv.ParseInt(frag.Get("expires_in"), 10, 64); err != nil {
         t.Fatal("Error parsing expires_in value into int", err)
      } else if expiry != authcache.TokenExpiry {
			t.Fatal("Request fragment contained bad expires_in", expiry)
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
   case <- redirect_reqs:
   case <- time.After(time.Second):
   }

	// Test using the access token
	apiUseTest(t, token)
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

	response2, err := http.Get(makeQuery(querymap, auth_url))
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

	token, ok := ret["token"]
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
   if !ok {
		t.Fatal("Expires Time not included in response", body)
	}
   if expiry, err := strconv.ParseInt(expiry_str, 10, 64); err != nil {
      t.Fatal("Expires Time could not be parsed into an int", err)
   } else if expiry != authcache.TokenExpiry {
		t.Fatal("Expires In Time not consistent.", expiry)
	}

	apiUseTest(t, token)
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
   querymap := map[string]string{
      "client_id":     "client2",
      "response_type": "code", // This means use auth code grant
      "redirect_uri":  redirect_url,
      "scope":         "",                    // Not implemented right now
      "state":         "authcode_grant_test", // Prevent's cross-site scripting
   }

   response, err := http.Get(makeQuery(querymap, auth_url))
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
   case req := <-redirect_reqs:
      q := req.URL.Query() // Parse query
      if errstr := q.Get("error"); errstr == "" {
         t.Fatal("Request Redirect did not contain access_denied error!", req.URL.String())
      } else if errstr != "access_denied" {
         t.Fatal("Request Fragment contained wrong error! ",
            q.Get("error"), q.Get("error_description"),
            q.Get("error_uri"))
      }
   case <-time.After(2 * time.Second):
      t.Fatal("Request not received in time.")
   }
}

func TestFailedImplicitGrant(t *testing.T) {
   querymap := map[string]string{
      "client_id":     "client2",
      "response_type": "token", // This means use implicit auth grant
      "redirect_uri":  redirect_url,
      "scope":         "",                    // Not implemented right now
      "state":         "implicit_grant_test", // Prevent's cross-site scripting
   }

   client := &http.Client{
      CheckRedirect: fragmentStrippingRedirector,
   }

   response, err := client.Get(makeQuery(querymap, auth_url))
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
      if errstr := frag.Get("error"); errstr == "" {
         t.Fatal("Fragment did not contain expected error!", fragstr)
      } else if errstr != "access_denied" {
         t.Fatal("Request Fragment contained bad error",
            frag.Get("error"), frag.Get("error_description"),
            frag.Get("error_uri"))
      }
   case <-time.After(2 * time.Second):
      t.Fatal("Request not received in time.")
   }
}