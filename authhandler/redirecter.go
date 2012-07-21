package authhandler

import (
	"github.com/yanatan16/goauth2"
	"net/url"
	"net/http"
)

// Redirecter is an AuthHandler that will redirect the request to another URI
type Redirecter struct {
	AuthCode, Implicit *url.URL
}

// Create an Redirecter AuthHandler
func NewRedirecter(authCodeUrl, implicitUrl string) (*Redirecter, error) {
	acurl, err := url.Parse(authCodeUrl)
	if err != nil {
		return nil, err
	}
	impurl, err := url.Parse(implicitUrl)
	if err != nil {
		return nil, err
	}
	re := &Redirecter{
		AuthCode: acurl,
		Implicit: impurl,
	}
	return re, nil
}

func (re *Redirecter) Authorize(w http.ResponseWriter, r *http.Request, oar *goauth2.OAuthRequest) {
	redirect := re.AuthCode
	redirect.RawQuery = r.URL.RawQuery
	http.Redirect(w, r, redirect.String(), 303)
}

func (re *Redirecter) AuthorizeImplicit(w http.ResponseWriter, r *http.Request, oar *goauth2.OAuthRequest) {
	redirect := re.Implicit
	redirect.RawQuery = r.URL.RawQuery
	http.Redirect(w, r, redirect.String(), 303)
}