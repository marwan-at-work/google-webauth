// Package webauth is an experimental package to add Google OAuth user flow to a web
// server.
package webauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/NYTimes/gizmo/auth"
	"github.com/NYTimes/gizmo/auth/gcp"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	kmsv1 "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type (
	// Authenticator leans on Google's OAuth user flow to capture a Google Identity JWS
	// and use it in a local, short lived HTTP cookie. The `Middleware` function manages
	// login redirects, OAuth callbacks, dropping the HTTP cookie and adding the JWS
	// claims information to the request context. User information and the JWS token can
	// be retrieved from the context via GetInfo function.
	// The user state in the login flow is encrypted using Google KMS. Ensure the service
	// account being used has permissions to encrypt and decrypt.
	Authenticator struct {
		cfg          Config
		secureCookie bool
		cookieDomain string
		callbackPath string

		keyName  string
		keys     *kms.KeyManagementClient
		verifier *auth.Verifier
		log      log.Logger
	}

	// Config encapsulates the needs of the Authenticator.
	Config struct {
		// CookieName will be used for the local HTTP cookie name.
		CookieName string

		// KMSKeyName is used by a Google KMS client for encrypting and decrypting state
		// tokens within the oauth exchange.
		KMSKeyName string

		// AuthConfig is used by Authenticator.Middleware and callback to enable the
		// Google OAuth flow.
		AuthConfig *oauth2.Config

		// HeaderExceptions can optionally be included. Any requests that include any of
		// the headers included will skip all Authenticator.Middlware checks and no
		// claims information will be added to the context.
		// This can be useful for unspoofable headers like Google App Engine's
		// "X-AppEngine-*" headers for Google Task Queues.
		HeaderExceptions []string

		// IDConfig will be used to verify the Google Identity JWS when it is inbound
		// in the HTTP cookie.
		IDConfig gcp.IdentityConfig
		// IDVerifyFunc allows developers to add their own verification on the user
		// claims. For example, one could enable access for anyone with an email domain
		// of "@example.com".
		IDVerifyFunc func(context.Context, gcp.IdentityClaimSet) bool

		// Logger will be used to log any errors encountered during the auth flow.
		Logger log.Logger
	}
)

// New will instantiate a new Authenticator.
func New(ctx context.Context, cfg Config) (Authenticator, error) {
	ks, err := gcp.NewIdentityPublicKeySource(ctx, cfg.IDConfig)
	if err != nil {
		return Authenticator{}, errors.Wrap(err, "unable to init key source")
	}
	u, err := url.Parse(cfg.AuthConfig.RedirectURL)
	if err != nil {
		return Authenticator{}, errors.Wrap(err, "unable to pasrse redirect URL")
	}
	keys, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return Authenticator{}, errors.Wrap(err, "unable to init KMS client")
	}
	return Authenticator{
		cfg:          cfg,
		keys:         keys,
		cookieDomain: strings.Split(u.Host, ":")[0],
		secureCookie: u.Scheme == "https",
		callbackPath: u.Path,
		verifier: auth.NewVerifier(ks, gcp.IdentityClaimsDecoderFunc,
			gcp.IdentityVerifyFunc(cfg.IDVerifyFunc)),
	}, nil
}

// LogOut can be used to clear an existing session. It will add an HTTP cookie with a -1
// "MaxAge" to the response to remove the cookie from the logged in user's browser.
func (c Authenticator) LogOut(w http.ResponseWriter) {
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
func (c Authenticator) Middleware(h http.Handler) http.Handler {
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

func (c Authenticator) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// verify state
	uri, ok := c.verifyState(ctx, q.Get("state"))
	if !ok {
		c.redirect(w, r)
		return
	}

	code := q.Get("code")
	if strings.TrimSpace(code) == "" {
		c.redirect(w, r)
		return
	}

	token, err := c.cfg.AuthConfig.Exchange(ctx, code)
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to exchange code")
		c.redirect(w, r)
		return
	}
	idI := token.Extra("id_token")
	if idI == nil {
		c.redirect(w, r)
		return
	}
	id, ok := idI.(string)
	if !ok {
		c.cfg.Logger.Log("message", "id_token was not a string",
			"error", "unexpectected type: "+fmt.Sprintf("%T", idI))
		c.redirect(w, r)
		return
	}

	// grab claims so we can use the expiration on our cookie
	claims, err := decodeClaims(id)
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to decode token")
		c.redirect(w, r)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    c.cfg.CookieName,
		Secure:  c.secureCookie,
		Value:   id,
		Domain:  c.cookieDomain,
		Expires: time.Unix(claims.Exp, 0),
	})
	http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
}

func (c Authenticator) verifyState(ctx context.Context, state string) (string, bool) {
	if state == "" {
		return "", false
	}
	rawState, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", false
	}

	decRes, err := c.keys.Decrypt(ctx, &kmsv1.DecryptRequest{
		Name:       c.cfg.KMSKeyName,
		Ciphertext: rawState,
	})
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to decrypt state",
			"state", state)
		return "", false
	}

	return string(decRes.Plaintext), true
}

func (c Authenticator) redirect(w http.ResponseWriter, r *http.Request) {
	state := "/" // can't be empty
	uri := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	// avoid redirect loops
	if strings.HasPrefix(uri, c.cfg.AuthConfig.RedirectURL) {
		uri = "/"
	}
	// encrypt current URL as state
	encRes, err := c.keys.Encrypt(r.Context(), &kmsv1.EncryptRequest{
		Name:      c.cfg.KMSKeyName,
		Plaintext: []byte(uri),
	})
	if err != nil {
		c.cfg.Logger.Log("error", err, "message", "unable to encrypt state")
	} else {
		state = base64.StdEncoding.EncodeToString(encRes.Ciphertext)
	}

	http.Redirect(w, r, c.cfg.AuthConfig.AuthCodeURL(state),
		http.StatusTemporaryRedirect)
}

type key int

const claimsKey key = 1

// GetUserClaims will return the Google identity claim set if it exists in the
// context. This can be used in coordination with the Authenticator.Middleware.
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
