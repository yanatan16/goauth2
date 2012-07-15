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
	CreateImplicitAccessToken(r *OAuthRequest) (token, token_type string, expiry int, err error)
	// Validate an authorization code is valid and generate access token
	// Return true if valid, false otherwise.
	CreateAccessToken(r *AccessTokenRequest) (token, token_type string, expiry int, err error)
	// Validate an access token is valid
	// Return true if valid, false otherwise.
	ValidateAccessToken(authorization_field string) (bool, error)
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

// AuthHandler
// AuthHandlers perform authentication with the resource owner
// It is important they follow OAuth 2.0 specification. For ease of use,
// A reference to the Store is passed in the OAuthRequest.
// Also, the functions AuthCodeRedirect and ImplicitRedirect will
// allow a handler to redirect back to the client in a spec-certified way.
type AuthHandler func(w http.ResponseWriter, r *http.Request, oar *OAuthRequest)

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
	ImplicitAuth, AuthCodeAuth AuthHandler
	errorURIs                  map[errorCode]string
}

// NewServer [...]
// store is a goauth2 Store which can be user implemented or
//	use the one that has users implement AuthCache and ClientStore
// authCodeHandler is a AuthHandler which will handle authentication
// 	of the resource owner during the auth code grant
// implicitHandler is a AuthHandler which will handle authentication
// 	of the resource owner during implicit grant
// Note: the handlers must follow the proper redirect patterns
func NewServer(store Store, authCodeHandler, implicitHandler AuthHandler) *Server {
	return &Server{
		Store:        store,
		ImplicitAuth: implicitHandler,
		AuthCodeAuth: authCodeHandler,
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
