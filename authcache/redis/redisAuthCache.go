package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	redis "github.com/simonz05/godis"
	"log"
)

// Implementation of the goauth2.AuthCache
// Note: Currently only supports bearer tokens
type RedisAuthCache struct {
	db                      *redis.Client
	CodeExpiry, TokenExpiry int64
}

// Create a redis-based implementation of goauth2.AuthCache
func NewRedisAuthCache(addr string, dbnum int, pass string) *RedisAuthCache {
	return &RedisAuthCache{
		db:          redis.New(addr, dbnum, pass),
		CodeExpiry:  120,
		TokenExpiry: 3600,
	}
}

func codeKey(code string) string {
	return fmt.Sprintf("code:%s", code)
}
func tokenKey(token string) string {
	return fmt.Sprintf("token:%s", token)
}

// Register an authorization code into the cache
// ClientID is the client requesting
// Scope is the requested access scope
// Redirect_uri is the redirect URI to save for checking on lookup
// Code is a generated random string to register with the request
func (ac *RedisAuthCache) RegisterAuthCode(clientID, scope, redirect_uri, code string) error {
	vars := map[string]string{
		"clientID":     clientID,
		"scope":        scope,
		"redirect_uri": redirect_uri,
	}
	val, err := json.Marshal(vars)
	if err != nil {
		return err
	}

	key := codeKey(code)

	err = ac.db.Set(key, val)
	if err != nil {
		return err
	}

	if valid, err := ac.db.Expire(key, int64(ac.CodeExpiry)); err != nil {
		return err
	} else if !valid {
		return errors.New("Invalid return from setting code expiration.")
	}

	return nil
}

// Register an access token into the cache
// ClientID is the client requesting
// Scope is the requested access scope
// Token is a generated random string to register with the request
// Returns the token type, expiration time (in seconds), and possibly an error
func (ac *RedisAuthCache) RegisterAccessToken(clientID, scope, token string) (ttype string, expiry int64, err error) {

	vars := map[string]string{
		"clientID": clientID,
		"scope":    scope,
	}
	val, err := json.Marshal(vars)
	if err != nil {
		log.Println("Error Marshalling variables for Redis Set", err)
		return "", 0, err
	}

	key := tokenKey(token)

	err = ac.db.Set(key, val)
	if err != nil {
		log.Println("Error performing Redis-Set", err)
		return "", 0, err
	}

	valid, err := ac.db.Expire(key, int64(ac.TokenExpiry))
	if err != nil {
		log.Println("Error performing Redis-Expire", err)
		return "", 0, err
	} else if !valid {
		err = errors.New("Invalid return from setting code expiration.")
		log.Println("Error performing Redis-Expire", err)
		return "", 0, err
	}

	return "bearer", ac.TokenExpiry, nil
}

// Lookup access token
// Code is the code passed from the user
// Returns the clientID, scope, and redirect URI registered with that code
func (ac *RedisAuthCache) LookupAuthCode(code string) (clientID, scope, redirect_uri string, err error) {

	key := codeKey(code)

	val, err := ac.db.Get(key)
	if err != nil {
		return
	}

	vars := make(map[string]string)
	err = json.Unmarshal(val, &vars)
	if err != nil {
		return
	}

	clientID, ok := vars["clientID"]
	if !ok {
		err = errors.New("ClientID not found in code lookup!")
	}
	scope, ok = vars["scope"]
	if !ok {
		err = errors.New("Scope not found in code lookup!")
	}
	redirect_uri, ok = vars["redirect_uri"]
	if !ok {
		err = errors.New("RedirectURI not found in code lookup!")
	}

	return
}

// Lookup an Access Token
// Token is the token passed from the client
// Return whether the token is valid
func (ac *RedisAuthCache) LookupAccessToken(token string) (bool, error) {

	key := tokenKey(token)

	// Using a special form of Get to check for nil without error
	if r := redis.SendStr(ac.db.Rw, "GET", key); r.Err != nil {
		return false, r.Err
	} else if r.Elem == nil {
		// Key does not exist
		return false, nil
	}

	return true, nil
}
