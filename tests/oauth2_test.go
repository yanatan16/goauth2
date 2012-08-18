package tests

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"encoding/json"
	"time"
	"net/url"
)

const (
	auth_port int = 16001
)

var (
	api_url string
)

func init() {
	go ExampleRunGoauth2Server(auth_port)
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
		t.Fatal("API Response Status code is bad", resp.Status, api_url)
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
	querymap := map[string]string{
		"client_id":     "client2",
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

// Test what happend when a bad response type
func TestBadResponseType(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "blah", // This means use auth code grant
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

		if errstr, ok := ret["error"]; !ok {
			t.Fatal("Error getting error field of json:", body)
		} else if errstr != "unsupported_response_type" {
			t.Error("Bad error value on response:", errstr)
		}
	}

	// Shouldn't get a redirect
	select {
	case <-redirect_reqs:
	case <-time.After(time.Second / 2):
	}
}

// Test what happend when a no response type
func TestNoResponseType(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
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

		if errstr, ok := ret["error"]; !ok {
			t.Fatal("Error getting error field of json:", body)
		} else if errstr != "invalid_request" {
			t.Error("Bad error value on response:", errstr)
		}
	}

	// Shouldn't get a redirect
	select {
	case <-redirect_reqs:
	case <-time.After(time.Second / 2):
	}
}

// Test what happend when a no response type
func TestBadRedirectType(t *testing.T) {
	querymap := map[string]string{
		"client_id":     "client1",
		"response_type": "code",
		"redirect_uri":  "hafda;rea",
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

		if errstr, ok := ret["error"]; !ok {
			t.Fatal("Error getting error field of json:", body)
		} else if errstr != "invalid_request" {
			t.Error("Bad error value on response:", errstr)
		}
	}

	// Shouldn't get a redirect
	select {
	case <-redirect_reqs:
	case <-time.After(time.Second / 2):
	}
}
