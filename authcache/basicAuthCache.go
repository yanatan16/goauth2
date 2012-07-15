// Package goauth2/authcache provides a basic implementation of an AuthCache as defined in package goauth2.
package authcache

import (
	"errors"
	"time"
)

const (
	CodeExpiry  int = 100
	TokenExpiry int = 3600
)

type CacheEntry struct {
	ClientID, Scope, RedirectURI string
}

// This is a struct that implements the AuthCache interface
// Note: It only handles bearer tokens
type BasicAuthCache struct {
	AuthCodes    map[string]*CacheEntry
	AccessTokens map[string]*CacheEntry
}

// Create a new Basic Auth Cache
func NewBasicAuthCache() *BasicAuthCache {
	return &BasicAuthCache{
		AuthCodes:    make(map[string]*CacheEntry),
		AccessTokens: make(map[string]*CacheEntry),
	}
}

// Register an authorization code into the cache
// ClientID is the client requesting
// Scope is the requested access scope
// Redirect_uri is the redirect URI to save for checking on lookup
// Code is a generated random string to register with the request
func (ac *BasicAuthCache) RegisterAuthCode(clientID, scope, redirect_uri, code string) (err error) {
	entry := &CacheEntry{
		ClientID:    clientID,
		Scope:       scope,
		RedirectURI: redirect_uri,
	}
	ac.AuthCodes[code] = entry

	go DelayedDelete(ac.AuthCodes, code, CodeExpiry)

	return nil
}

// Register an access token into the cache
// ClientID is the client requesting
// Scope is the requested access scope
// Token is a generated random string to register with the request
// Returns the token type, expiration time (in seconds), and possibly an error
func (ac *BasicAuthCache) RegisterAccessToken(clientID, scope, token string) (ttype string, expiry int, err error) {
	entry := &CacheEntry{
		ClientID: clientID,
		Scope:    scope,
	}
	ac.AccessTokens[token] = entry

	go DelayedDelete(ac.AccessTokens, token, TokenExpiry)

	return "bearer", TokenExpiry, nil
}

// Lookup access token
// Code is the code passed from the user
// Returns the clientID, scope, and redirect URI registered with that code
func (ac *BasicAuthCache) LookupAuthCode(code string) (clientID, scope, redirect_uri string, err error) {
	entry, ok := ac.AuthCodes[code]
	if !ok {
		return "", "", "", errors.New("AuthCode not found in Cache!")
	}

	return entry.ClientID, entry.Scope, entry.RedirectURI, nil
}

// Lookup an Access Token
// Token is the token passed from the client
// Return whether the token is valid
func (ac *BasicAuthCache) LookupAccessToken(token string) (bool, error) {
	_, ok := ac.AccessTokens[token]

	return ok, nil
}

// DelayedDelete will way secs seconds before deleting key from map m
func DelayedDelete(m map[string]*CacheEntry, key string, secs int) {
	<-time.After(time.Duration(secs) * time.Second)
	delete(m, key)
}
