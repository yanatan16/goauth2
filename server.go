package goauth2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ----------------------------------------------------------------------------

// Store [...]
type Store interface {
	// A Client is always returned -- it is nil only if ClientID is invalid.
	// Use the error to indicate denied or unauthorized access.
	GetClient(clientID string) (Client, error)
	// Create the authorization code for the Authorization Code Grant flow
	// Return a ServerError if the authorization code cannot be requested
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.1
	CreateAuthCode(r OAuthRequest) (string, error)
	// Create an access token for the Implicit Token Grant flow
	// The token type, token and expiry should conform to the response guidelines
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2.2
	CreateImplicitAccessToken(r OAuthRequest) \
		(token, token_type string, expiry int, err error)
	// Validate an authorization code is valid and generate access token
	// Return true if valid, false otherwise.
	CreateAccessToken(r AccessTokenRequest) \
		(token, token_type string, expiry int, err error)
	// Validate an access token is valid
	// Return true if valid, false otherwise.
	ValidateAccessToken(authorization_field string) bool
}

// ----------------------------------------------------------------------------

// Client is a client registered with the authorization server.
type Client interface {
	// Unique identifier for the client.
	ID() string
	// The registered client type ("confidential" or "public") as decribed in:
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-2.1
	Type() string
	// The registered redirect_uri.
	RedirectURI() string
	// Validates that the provided redirect_uri is valid. It must return the
	// same provided URI or an empty string if it is not valid.
	// The specification is permissive and even allows multiple URIs, so the
	// validation rules are up to the server implementation.
	// Ref: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.2
	ValidateRedirectURI(string) string
}

// ----------------------------------------------------------------------------

// OAuthRequest [...]
type OAuthRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
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
		ClientID:     v.Get("client_id"),
		ResponseType: v.Get("response_type"),
		RedirectURI:  v.Get("redirect_uri"),
		Scope:        v.Get("scope"),
		State:        v.Get("state"),
	}
}

// NewAccessTokenRequest [...]
func (s *Server) NewAccessTokenRequest(r *http.Request) *AccessTokenRequestRequest {
	v := r.URL.Query()
	return &NewAccessTokenRequest{
		GrantType:     v.Get("grant_type"),
		Code: v.Get("code"),
		RedirectURI:  v.Get("redirect_uri")
	}
}

// ----------------------------------------------------------------------------

// Server [...]
type Server struct {
	Store     Store
	errorURIs map[errorCode]string
}

// NewServer [...]
func NewServer(store Store) *Server {
	return &Server{
		Store: store,
		errorURIs: make(map[errorCode]string),
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

// ----------------------------------------------------------------------------

// setQueryPairs sets non-empty values in a url.Values.
//
// This is just a convenience to avoid checking for emptiness for each value.
func setQueryPairs(v url.Values, pairs ...string) {
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

// randomString generates authorization codes or tokens with a given strength.
func randomString(strength int) string {
	s := make([]byte, strength)
	if _, err := rand.Read(s); err != nil {
		return ""
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}
