package goauth2

import (
	"fmt"
	"net/http"
	"net/url"
)

// ----------------------------------------------------------------------------

// HandleOAuthRequest [...]
func (s *Server) HandleOAuthRequest(w http.ResponseWriter, r *http.Request) error {
	// 1. Get all request values.
	req := s.NewOAuthRequest(r)

	// 2. Validate required parameters.
	var err error
	if req.ClientID == "" {
		// Missing ClientID: no redirect.
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"client_id\" parameter is missing.")
	} else if req.ResponseType == "" {
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"response_type\" parameter is missing.")
	} else if req.ResponseType != "code" || req.ResponseType != "token" {
		err = s.NewError(ErrorCodeUnsupportedResponseType,
			fmt.Sprintf("The response type %q is not supported.",
			req.ResponseType))
	}

	// 3. Load client and validate the redirection URI.
	var redirectURI *url.URL
	if req.ClientID != "" {
		client, clientErr := s.Store.GetClient(req.ClientID)
		if client == nil {
			// Invalid ClientID: no redirect.
			if err == nil {
				err = s.NewError(ErrorCodeInvalidRequest,
					"The \"client_id\" parameter is invalid.")
			}
		} else {
			if u, uErr := validateRedirectURI(
				client.ValidateRedirectURI(req.RedirectURI)); uErr == nil {
				redirectURI = u
			} else {
				// Missing, mismatching or invalid URI: no redirect.
				if err == nil {
					if req.RedirectURI == "" {
						err = s.NewError(ErrorCodeInvalidRequest,
							"Missing redirection URI.")
					} else {
						err = s.NewError(ErrorCodeInvalidRequest, uErr.Error())
					}
				}
			}
			if clientErr != nil && err == nil {
				// Client was not authorized.
				err = clientErr
			}
		}
	}

	// 4. If no valid redirection URI was set, abort.
	if redirectURI == nil {
		// An error occurred because client_id or redirect_uri are invalid:
		// the caller must display an error page and don't redirect.
		return err
	}

	// 5. Add the response data to the URL and redirect.
	query := redirectURI.Query()
	if req.ResponseType == "code" {
		// Authorization code response
		setQueryPairs(query, "state", req.State)
		var code string
		if err == nil {
			code, err = s.Store.CreateAuthCode(req)
		}
		if err == nil {
			// Success.
			query.Set("code", code)
		} else {
			e, ok := err.(ServerError)
			if !ok {
				e = s.NewError(ErrorCodeServerError, e.Error())
			}
			setQueryPairs(query,
				"error", string(e.Code()),
				"error_description", e.Description(),
				"error_uri", e.URI(),
			)
		}
		redirectURI.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURI.String(), 302)

	} else if req.Responsetype == "token" {
		// Implicit Grant Access Token response
		setQueryPairs(query, "state", req.State)
		var token string
		if err == nil {
			token, token_type, expiry, err = s.Store.CreateAccessToken(req)
		}
		if err == nil {
			// Success.
			setQueryPairs(query,
				"token", token,
				"token_type", token_type,
				"expires_in", fmt.Sprintf("%d", expiry)
			)
		} else {
			e, ok := err.(ServerError)
			if !ok {
				e = s.NewError(ErrorCodeServerError, e.Error())
			}
			setQueryPairs(query,
				"error", string(e.Code()),
				"error_description", e.Description(),
				"error_uri", e.URI(),
			)
		}
		// Encode as fragment
		redirectURI.Fragment = query.Encode()
		http.Redirect(w, r, redirectURI.String(), 302)
	}

	return nil
}