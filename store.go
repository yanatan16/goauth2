package goauth2

// Authorization Cache
// This is an interface that registers and looks up authorization codes
// and access tokens with corresponding information.
type AuthCache interface {
	// Register an authorization code into the cache
	// ClientID is the client requesting
	// Scope is the requested access scope
	// Redirect_uri is the redirect URI to save for checking on lookup
	// Code is a generated random string to register with the request
	RegisterAuthCode(clientID, scope, redirect_uri, code string) error

	// Register an access token into the cache
	// ClientID is the client requesting
	// Scope is the requested access scope
	// Token is a generated random string to register with the request
	// Returns the token type, expiration time (in seconds), and possibly an error
	RegisterAccessToken(clientID, scope, token string) (ttype string, expiry int, err error)

	// Lookup access token
	// Code is the code passed from the user
	// Returns the clientID, scope, and redirect URI registered with that code
	LookupAuthCode(code string) (clientID, scope, redirect_uri string, err error)

	// Lookup an Access Token
	// Token is the token passed from the client
	// Return whether the token is valid
	LookupAccessToken(token string) (bool, error)
}

// ClientStore is an interface for validating whether a client is valid
type ClientStore interface {
	// Check whether a clientID is valid
	ValidClient(clientID string) (bool, error)
}

// ----------------------------------------------------------------------------

// An implementation of the goauth2 store that abstracts away the
// work into 3 parts:
//	1: Token/Code generation and error handling is done for the user
//	2: Caching active tokens and codes into an AuthCache interface
//	3: Looking up clients into the ClientStore interface
// Note: Currently only supports public clients with bearer tokens
type StoreImpl struct {
	Clients ClientStore
	Backend AuthCache
}

// ----------------------------------------------------------------------------

func NewStore(clients ClientStore, backend AuthCache) *StoreImpl {
	return &StoreImpl{
		clients,
		backend,
	}
}

// GetClient
// A Client is always returned -- it is nil only if ClientID is invalid.
// Use the error to indicate denied or unauthorized access.
// Note: Currently only provides public clients
func (s *StoreImpl) GetClient(clientID string) (Client, error) {
	if valid, err := s.Clients.ValidClient(clientID); err != nil {
		return nil, err
	} else if valid {
		return NewClient(clientID, "public"), nil
	}
	err := NewServerError(ErrorCodeUnauthorizedClient,
		"ClientID not valid.", "")
	return nil, err
}

// Create the authorization code for the Authorization Code Grant flow
// Return a ServerError if the authorization code cannot be requested
// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1.1
func (s *StoreImpl) CreateAuthCode(r *OAuthRequest) (string, error) {
	code := <-RandStr
	if err := s.Backend.RegisterAuthCode(r.ClientID,
		r.Scope, r.RedirectURI, code); err != nil {
		return "", err
	}

	return code, nil
}

// Create an access token for the Implicit Token Gr`ant flow
// The token type, token and expiry should conform to the response guidelines
// http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2.2
func (s *StoreImpl) CreateImplicitAccessToken(r *OAuthRequest) (token, token_type string, expiry int, err error) {

	token = <-RandStr
	ttype, exp, err := s.Backend.RegisterAccessToken(r.ClientID, r.Scope, token)

	if err != nil {
		return "", "", 0, err
	}
	return token, ttype, exp, nil
}

// Validate an authorization code is valid and generate access token
// Return true if valid, false otherwise.
func (s *StoreImpl) CreateAccessToken(r *AccessTokenRequest) (token, token_type string, expiry int, err error) {

	cid, scope, uri, err := s.Backend.LookupAuthCode(r.Code)
	if err != nil {
		return
	}

	// Check Valid Redirect URI
	if uri != r.RedirectURI {
		err = NewServerError(ErrorCodeBadRedirectURI, "Redirect URI Incorrect.", "")
		return
	}

	// All good
	token = <-RandStr
	ttype, exp, err := s.Backend.RegisterAccessToken(cid, scope, token)
	if err != nil {
		return "", "", 0, err
	}

	return token, ttype, exp, nil
}

// Validate an access token is valid
// Return true if valid, false otherwise.
// Note: Supports only bearer tokens
func (s *StoreImpl) ValidateAccessToken(authorization_field string) (bool, error) {
	token := authorization_field // TODO

	valid, err := s.Backend.LookupAccessToken(token)
	if err != nil {
		return false, err
	}

	return valid, nil
}
