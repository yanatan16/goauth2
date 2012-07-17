// This package provides a few ways to test a server implementing goauth2
// with their specific AuthCache implementation
package goauth2

import (
   "github.com/yanatan16/goauth2/authcache"
   "net/http"
   "log"
   "fmt"
   "time"
)

// Example way to run an goauth2 server
func ExampleRunGoauth2Server(port int) {
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
      Addr:           fmt.Sprintf(":%d",port),
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
