package goauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

// ----------------------------------------------------------------------------

// Store [...]
type Store interface {
	// Create the authorization code for the Authorization Code Grant flow
	// Return a ServerError if the authorization code cannot be requested
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.1
	CreateAuthCode(r *OAuthRequest) (string, error)
	// Create an access token for the Implicit Token Grant flow
	// The token type, token and expiry should conform to the response guidelines
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2.2
	CreateImplicitAccessToken(r *OAuthRequest) (token, token_type string, expiry int64, err error)
	// Validate an authorization code is valid and generate access token
	// Return true if valid, false otherwise.
	CreateAccessToken(r *AccessTokenRequest) (token, token_type string, expiry int64, err error)
	// Validate an access token is valid
	// Return true if valid, false otherwise.
	ValidateAccessToken(authorization_field string) (bool, error)
}

// AuthHandler performs authentication with the resource owner
// It is important they follow OAuth 2.0 specification. For ease of use,
// A reference to the Store is passed in the OAuthRequest.
type AuthHandler interface {
	// Authorize a client using the Authorization Code Grant Flow
	// After authorization, the server should redirect using
	// oar.AuthCodeRedirect()
	Authorize(w http.ResponseWriter, r *http.Request, oar *OAuthRequest)
	// Authorize a client using the Implicit Grant Flow
	// After authorization, the server should redirect using
	// oar.AuthCodeRedirect()
	AuthorizeImplicit(w http.ResponseWriter, r *http.Request, oar *OAuthRequest)
}

// ----------------------------------------------------------------------------

// OAuthRequest [...]
type OAuthRequest struct {
	ClientID        string
	ResponseType    string
	redirectURI_raw string
	RedirectURI     *url.URL
	Scope           string
	State           string

	// For accessing store functions, such as creating auth codes
	Store Store
}

// AccessTokenRequest [...]
type AccessTokenRequest struct {
	GrantType   string
	Code        string
	RedirectURI string
}

// NewOAuthRequest [...]
func (s *Server) NewOAuthRequest(r *http.Request) *OAuthRequest {
	v := r.URL.Query()
	return &OAuthRequest{
		ClientID:        v.Get("client_id"),
		ResponseType:    v.Get("response_type"),
		redirectURI_raw: v.Get("redirect_uri"),
		Scope:           v.Get("scope"),
		State:           v.Get("state"),
		Store:           s.Store,
	}
}

// NewAccessTokenRequest [...]
func (s *Server) NewAccessTokenRequest(r *http.Request) *AccessTokenRequest {
	v := r.URL.Query()
	return &AccessTokenRequest{
		GrantType:   v.Get("grant_type"),
		Code:        v.Get("code"),
		RedirectURI: v.Get("redirect_uri"),
	}
}

// ----------------------------------------------------------------------------

// Server [...]
type Server struct {
	Store                      Store
	Auth AuthHandler
	errorURIs                  map[errorCode]string
}

// NewServer 
// Create a new OAuth 2.0 Server
// cache is an AuthCache interface to hold the code and token
func NewServer(cache AuthCache, auth AuthHandler) *Server {
	store := NewStore(cache)
	return &Server{
		Store:        store,
		Auth: auth,
		errorURIs:    make(map[errorCode]string),
	}
}

// RegisterErrorURI [...]
func (s *Server) RegisterErrorURI(code errorCode, uri string) {
	s.errorURIs[code] = uri
}

// NewError [...]
func (s *Server) NewError(code errorCode, description string) ServerError {
	return NewServerError(code, description, s.errorURIs[code])
}

func (s *Server) InterpretError(err error) ServerError {
	e, ok := err.(ServerError)
	if !ok {
		e = s.NewError(ErrorCodeServerError, e.Error())
	} else if e.uri == "" {
		e = s.NewError(e.code, e.description)
	}
	return e
}

// ----------------------------------------------------------------------------

type Setter interface {
	Set(a, b string)
}

// setQueryPairs sets non-empty values in a url.Values.
//
// This is just a convenience to avoid checking for emptiness for each value.
func setQueryPairs(v Setter, pairs ...string) {
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			v.Set(pairs[i], pairs[i+1])
		}
	}
}

// validateRedirectURI checks if a redirection URL is valid.
func validateRedirectURI(uri string) (u *url.URL, err error) {
	u, err = url.Parse(uri)
	if err != nil {
		err = fmt.Errorf("The redirection URI is malformed: %q.", uri)
	} else if !u.IsAbs() {
		err = fmt.Errorf("The redirection URI must be absolute: %q.", uri)
	} else if u.Fragment != "" {
		err = fmt.Errorf(
			"The redirection URI must not contain a fragment: %q.", uri)
	}
	return
}
