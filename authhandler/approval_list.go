// This package provides a few implementations of goauth2.AuthHandler
// for use in embedding the goauth2 server.
package authhandler

import (
	"github.com/yanatan16/goauth2"
	"net/http"
)

// ApprovalList is an AuthHandler that will automatically accept or 
// reject a client based on the policy given to the ApprovalList
type ApprovalList struct {
	Default bool
	List map[string]bool
}

// Create an ApprovalList AuthHandler that has an auto-deny default policy
func NewWhiteList(list ...string) *ApprovalList {
	al := &ApprovalList{
		Default: false,
		List: make(map[string]bool),
	}
	for _, name := range list {
		al.List[name] = true
	}
	return al
}

// Create an ApprovalList AuthHandler that has an auto-allow default policy
func NewBlackList(list ...string) *ApprovalList {
	al := &ApprovalList{
		Default: true,
		List: make(map[string]bool),
	}
	for _, name := range list {
		al.List[name] = false
	}
	return al
}


func (a *ApprovalList) Authorize(w http.ResponseWriter, r *http.Request, oar *goauth2.OAuthRequest) {
	valid, ok := a.List[oar.ClientID]
	if !ok {
		valid = a.Default
	}

	var err error
	if !valid {
		err = goauth2.NewServerError(goauth2.ErrorCodeAccessDenied, "access denied", "")
	}

	oar.AuthCodeRedirect(w, r, err)
}

func (a *ApprovalList) AuthorizeImplicit(w http.ResponseWriter, r *http.Request, oar *goauth2.OAuthRequest) {
	valid, ok := a.List[oar.ClientID]
	if !ok {
		valid = a.Default
	}

	var err error
	if !valid {
		err = goauth2.NewServerError(goauth2.ErrorCodeAccessDenied, "access denied", "")
	}

	oar.ImplicitRedirect(w, r, err)
}