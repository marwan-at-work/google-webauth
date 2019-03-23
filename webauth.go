// package webauth is an experimental package to add Google OAuth user flow to a web
// server.
package webauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NYTimes/gizmo/auth"
	"github.com/NYTimes/gizmo/auth/gcp"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type (
	// Client leans on Google's OAuth user flow to capture a Google Identity JWS and use
	// it in a local, short lived HTTP cookie. The `Middleware` function manages login
	// redirects, OAuth callbacks, dropping the HTTP cookie and adding the JWS claims
	// information to the request context. User information and the JWS token can be
	// retrieved from the context via GetInfo function.
	Client struct {
		cfg          Config
		secureCookie bool
		cookieDomain string
		callbackPath string

		verifier *auth.Verifier
		log      log.Logger
	}

	// Config encapsulates the needs of the Client.
	Config struct {
		// CookieName will be used for the HTTP cookie name.
		CookieName string

		// LandingURI is the URI Client.Middleware will redirect to after a successful
		// callback.
		LandingURI string
		// AuthConfig is used by Client.Middleware and callback to enable the Google
		// OAuth flow.
		AuthConfig *oauth2.Config

		// HeaderExceptions can optionally be included. Any requests that include any of
		// the headers included will skip all Client.Middlware checks and no claims
		// information will be added to the context.
		// This can be useful for unspoofable headers like Google App Engine's
		// "X-AppEngine-*" headers for Google Task Queues.
		HeaderExceptions []string

		// IDConfig will be used to verify the Google Identity JWS when it is inbound
		// in the HTTP cookie.
		IDConfig gcp.IdentityConfig
		// IDVerifyFunc allows developers to add their own verification on the user
		// claims. For example, one could enable access for anyone with an email domain
		// of "@google.com".
		IDVerifyFunc func(context.Context, gcp.IdentityClaimSet) bool
	}
)

// NewClient will instantiate a new Client.
func NewClient(ctx context.Context, cfg Config, lg log.Logger) (Client, error) {
	ks, err := gcp.NewIdentityPublicKeySource(ctx, cfg.IDConfig)
	if err != nil {
		return Client{}, errors.Wrap(err, "unable to init key source")
	}
	u, err := url.Parse(cfg.AuthConfig.RedirectURL)
	if err != nil {
		return Client{}, errors.Wrap(err, "unable to pasrse redirect URL")
	}

	return Client{
		cfg:          cfg,
		cookieDomain: strings.Split(u.Host, ":")[0],
		secureCookie: u.Scheme == "https",
		callbackPath: u.Path,
		verifier: auth.NewVerifier(ks, gcp.IdentityClaimsDecoderFunc,
			gcp.IdentityVerifyFunc(cfg.IDVerifyFunc)),
		log: lg,
	}, nil
}

// ClearCookie can be used within a "log out" flow. It will add an HTTP cookie with a -1
// "MaxAge" to the response to remove the cookie from the logged in user's browser.
func (c Client) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    c.cfg.CookieName,
		Domain:  c.cookieDomain,
		Value:   "",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
}

// Middleware will handle login redirects, OAuth callbacks, header exceptions, verifying
// inbound Google ID JWS' within HTTP cookies and, if the user passes all checks, it will
// add the user claims to the inbound request context.
func (c Client) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == c.callbackPath {
			c.callbackHandler(w, r)
			return
		}

		// if one of the 'exception' headers exists, let the request pass through
		// this is nice for unspoofable headers like 'X-Appengine-*'.
		for _, hdr := range c.cfg.HeaderExceptions {
			if r.Header.Get(hdr) != "" {
				h.ServeHTTP(w, r)
				return
			}
		}

		// ***all other endpoints must have a cookie***

		ck, err := r.Cookie(c.cfg.CookieName)
		if err != nil || ck == nil {
			c.redirect(w, r)
			return
		}

		verified, err := c.verifier.Verify(r.Context(), ck.Value)
		if err != nil {
			c.redirect(w, r)
			return
		}
		if !verified {
			c.redirect(w, r)
			return
		}

		claims, err := decodeClaims(ck.Value)
		if err != nil {
			c.redirect(w, r)
			return
		}

		// add the user claims to the context and call the handlers below
		r = r.WithContext(context.WithValue(r.Context(), claimsKey, claims))
		h.ServeHTTP(w, r)
	})
}

func (c Client) callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if strings.TrimSpace(code) == "" {
		c.redirect(w, r)
		return
	}

	ctx := r.Context()
	token, err := c.cfg.AuthConfig.Exchange(ctx, code, oauth2.ApprovalForce)
	if err != nil {
		c.log.Log("error", err, "message", "unable to exchange code")
		c.redirect(w, r)
		return
	}
	id := token.Extra("id_token")
	if id == nil {
		c.redirect(w, r)
		return
	}

	// grab claims so we can use the expiration on our cookie
	claims, err := decodeClaims(id.(string))
	if err != nil {
		c.log.Log("error", err, "message", "unable to decode token")
		c.redirect(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    c.cfg.CookieName,
		Secure:  c.secureCookie,
		Value:   id.(string),
		Domain:  c.cookieDomain,
		Expires: time.Unix(claims.Exp, 0),
	})

	http.Redirect(w, r, c.cfg.LandingURI, http.StatusTemporaryRedirect)
}

func (c Client) redirect(w http.ResponseWriter, r *http.Request) {
	// TODO come up with better state token mgmt
	http.Redirect(w, r, c.cfg.AuthConfig.AuthCodeURL("state"),
		http.StatusTemporaryRedirect)
}

type key int

const claimsKey key = 1

// GetUserClaims will return the Google ID claim set if it exists in the
// context. This can be used in coordination with the Client.Middleware.
func GetUserClaims(ctx context.Context) (gcp.IdentityClaimSet, error) {
	var claims gcp.IdentityClaimSet
	clms := ctx.Value(claimsKey)
	if clms == nil {
		return claims, errors.New("claims not found")
	}
	return clms.(gcp.IdentityClaimSet), nil
}

func decodeClaims(token string) (gcp.IdentityClaimSet, error) {
	var claims gcp.IdentityClaimSet
	s := strings.Split(token, ".")
	if len(s) < 2 {
		return claims, errors.New("jws: invalid token received")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return claims, err
	}
	err = json.Unmarshal(decoded, &claims)
	if err != nil {
		return claims, err
	}
	return claims, nil
}
