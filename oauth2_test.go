package goauth2

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

const (
	auth_port int = 15697
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

