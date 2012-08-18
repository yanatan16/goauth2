package goauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

// Redirect an OAuth Authorization Code Flow Request
// If err is nil, the request is successful
// If err is not nil, then the error will be included in the redirect
func (req *OAuthRequest) AuthCodeRedirect(w http.ResponseWriter, r *http.Request, err error) {

	query := req.RedirectURI.Query()

	setQueryPairs(query, "state", req.State)

	var code string
	if err == nil {
		code, err = req.Store.CreateAuthCode(req)
	}
	if err == nil {
		query.Set("code", code)
	} else {
		if e, ok := err.(ServerError); ok {
			setQueryPairs(query,
				"error", string(e.Code()),
				"error_description", e.Description(),
				"error_uri", e.URI(),
			)
		} else {
			setQueryPairs(query,
				"error", string(ErrorCodeAccessDenied),
				"error_description", err.Error(),
				"error_uri", "",
			)
		}
	}
	req.RedirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, req.RedirectURI.String(), 302)
}

// Redirect an OAuth Implicit Grant Flow Request
// If err is nil, the request is successful
// If err is not nil, then the error will be included in the redirect
func (req *OAuthRequest) ImplicitRedirect(w http.ResponseWriter, r *http.Request, err error) {

	query, err2 := url.ParseQuery(req.RedirectURI.Fragment)
	if err2 != nil {
		err = NewServerError(ErrorCodeBadRedirectURI, "Can't parse redirect fragment.", "")
	}

	setQueryPairs(query, "state", req.State)

	if err == nil {
		token, token_type, expiry, err :=
			req.Store.CreateImplicitAccessToken(req)
		if err == nil {
			setQueryPairs(query,
				"token", token,
				"token_type", token_type,
			)
			if expiry > 0 {
				setQueryPairs(query, "expires_in", fmt.Sprintf("%d", expiry))
			}
		}
	}
	if err != nil {
		e, ok := err.(ServerError)
		if ok {
			setQueryPairs(query,
				"error", string(e.Code()),
				"error_description", e.Description(),
				"error_uri", e.URI(),
			)
		} else {
			setQueryPairs(query,
				"error", string(ErrorCodeAccessDenied),
				"error_description", err.Error(),
				"error_uri", "",
			)
		}
	}

	// Encode as a fragment
	req.RedirectURI.Fragment = query.Encode()
	http.Redirect(w, r, req.RedirectURI.String(), 302)
}
