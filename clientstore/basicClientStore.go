// Package goauth2/clientstore implements a basic version of the ClientStore interface from goauth2
package clientstore

// A basic implementation of the ClientStore interface
type BasicClientStore map[string]bool

// Create a BasicClientStore object
func NewBasicClientStore() BasicClientStore {
	return BasicClientStore(make(map[string]bool))
}

// Add a clientID to the valid list
func (cs BasicClientStore) AddClient(clientID string) {
	cs[clientID] = true
}

// Check whether a clientID is valid 
func (cs BasicClientStore) ValidClient(clientID string) (bool, error) {
	_, ok := cs[clientID]
	return ok, nil
}
