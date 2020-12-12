package oidc

import (
	"bytes"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/cap/oidc/internal/strutils"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TestProvider is a local http server that supports test provider capabilities
// which makes writing tests much easier.  Much of this TestProvider
// design/implementation comes from Consul's oauthtest package. A big thanks to
// the original package's contributors.
//
// It's important to remember that the TestProvider is stateful (see any of it's
// receiver functions that begin with Set*).
//
//  Once you've started a TestProvider http server with StartTestProvider(),
//  the following test endpoints are supported:
//
//    * GET /.well-known/openid-configuration    OIDC Discovery
//
//    * GET or POST  /authorize                  OIDC authorization (supporting both
//                                               the authorization code flow and the implicit
//                                               flow with form_post):
//
//    * POST /token                              OIDC token
//
//    * GET /userinfo                            OAuth UserInfo
//
//    * GET /.well-known/jwks.json               JWKs used to verify issued JWT tokens
//    * GET /.well-known/invalid-jwks.json       Invalid JWKs
//    * GET /.well-known/missing-jwks.json       Missing JWKs
type TestProvider struct {
	httpServer *httptest.Server
	caCert     string

	jwks                *jose.JSONWebKeySet
	allowedRedirectURIs []string
	replySubject        string
	replyUserinfo       map[string]interface{}
	replyExpiry         time.Duration

	mu                sync.Mutex
	clientID          string
	clientSecret      string
	expectedAuthCode  string
	expectedAuthNonce string
	customClaims      map[string]interface{}
	customAudiences   []string
	omitAuthTimeClaim bool
	omitIDToken       bool
	omitAccessToken   bool
	disableUserInfo   bool
	nowFunc           func() time.Time

	// privKey *ecdsa.PrivateKey
	privKey crypto.PrivateKey
	pubKey  crypto.PublicKey
	alg     Alg

	t *testing.T
}

// Stop stops the running TestProvider.
func (p *TestProvider) Stop() {
	p.httpServer.Close()
}

// StartTestProvider creates and starts a running TestProvider http server.
func StartTestProvider(t *testing.T, opt ...Option) *TestProvider {
	t.Helper()
	require := require.New(t)
	opts := getTestProviderOpts(opt...)

	p := &TestProvider{
		t:            t,
		nowFunc:      time.Now,
		customClaims: map[string]interface{}{},
		replyExpiry:  5 * time.Second,

		allowedRedirectURIs: []string{
			"https://example.com",
		},
		replySubject: "alice@example.com",
		replyUserinfo: map[string]interface{}{
			"dob":           "1978",
			"friend":        "bob",
			"nickname":      "A",
			"advisor":       "Faythe",
			"nosy-neighbor": "Eve",
		},
	}

	p.pubKey, p.privKey = TestGenerateKeys(t)
	p.alg = ES256
	p.jwks = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: p.pubKey,
			},
		},
	}
	p.httpServer = httptestNewUnstartedServerWithPort(t, p, opts.withPort)
	p.httpServer.Config.ErrorLog = log.New(ioutil.Discard, "", 0)
	p.httpServer.StartTLS()
	t.Cleanup(p.httpServer.Close)

	cert := p.httpServer.Certificate()

	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(err)
	p.caCert = buf.String()

	return p
}

// testProviderOptions is the set of available options for TestProvider
// functions
type testProviderOptions struct {
	withPort int
}

// testProviderDefaults is a handy way to get the defaults at runtime and during unit
// tests.
func testProviderDefaults() testProviderOptions {
	return testProviderOptions{}
}

// getTestProviderOpts gets the test provider defaults and applies the opt
// overrides passed in
func getTestProviderOpts(opt ...Option) testProviderOptions {
	opts := testProviderDefaults()
	ApplyOpts(&opts, opt...)
	return opts
}

// WithTestPort provides an optional port for the test provider. Valid for: TestProvider
func WithTestPort(port int) Option {
	return func(o interface{}) {
		if o, ok := o.(*testProviderOptions); ok {
			o.withPort = port
		}
	}
}

// SetExpectedExpiry is for configuring the expected expiry for any JWTs issued
// by the provider (the default is 5 seconds)
func (p *TestProvider) SetExpectedExpiry(exp time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.replyExpiry = exp
}

// SetClientCreds is for configuring the client information required for the
// OIDC workflows.
func (p *TestProvider) SetClientCreds(clientID, clientSecret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clientID = clientID
	p.clientSecret = clientSecret
}

// ClientCreds returns the client information required for the
// OIDC workflows.
func (p *TestProvider) ClientCreds() (clientID, clientSecret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientID, p.clientSecret
}

// SigningAlgorithm returns the algorithm used to sign JWTs for the test provider.
func (p *TestProvider) SigningAlgorithm() Alg {
	return ES256
}

// SetExpectedAuthCode configures the auth code to return from /auth and the
// allowed auth code for /token.
func (p *TestProvider) SetExpectedAuthCode(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedAuthCode = code
}

// SetExpectedAuthNonce configures the nonce value required for /auth.
func (p *TestProvider) SetExpectedAuthNonce(nonce string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedAuthNonce = nonce
}

// SetAllowedRedirectURIs allows you to configure the allowed redirect URIs for
// the OIDC workflow. If not configured a sample of "https://example.com" is
// used.
func (p *TestProvider) SetAllowedRedirectURIs(uris []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedRedirectURIs = uris
}

// SetCustomClaims lets you set claims to return in the JWT issued by the OIDC
// workflow.
func (p *TestProvider) SetCustomClaims(customClaims map[string]interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.customClaims = customClaims
}

// SetCustomAudience configures what audience value to embed in the JWT issued
// by the OIDC workflow.
func (p *TestProvider) SetCustomAudience(customAudiences ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.customAudiences = customAudiences
}

// SetNowFunc configures how the test provider will determine the current time.  The
// default is time.Now()
func (p *TestProvider) SetNowFunc(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nowFunc = now
}

// SetOmitAuthTimeClaim turn on/off the omitting of an auth_time claim from
// id_tokens from the /token endpoint.  If set to true, the test provider will
// not include the auth_time claim in issued id_tokens from the /token endpoint.
func (p *TestProvider) SetOmitAuthTimeClaim(omitAuthTime bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitAuthTimeClaim = omitAuthTime
}

// SetOmitIDTokens turn on/off the omitting of id_tokens from the /token
// endpoint.  If set to true, the test provider will not omit (issue) id_tokens
// from the /token endpoint.
func (p *TestProvider) SetOmitIDTokens(omitIDTokens bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitIDToken = omitIDTokens
}

// OmitAccessTokens turn on/off the omitting of access_tokens from the /token
// endpoint.  If set to true, the test provider will not omit (issue)
// access_tokens from the /token endpoint.
func (p *TestProvider) SetOmitAccessTokens(omitAccessTokens bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitAccessToken = true
}

// DisableUserInfo makes the userinfo endpoint return 404 and omits it from the
// discovery config.
func (p *TestProvider) DisableUserInfo() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disableUserInfo = true
}

// Addr returns the current base URL for the test provider's running webserver,
// which can be used as an OIDC issuer for discovery.
func (p *TestProvider) Addr() string { return p.httpServer.URL }

// CACert returns the pem-encoded CA certificate used by the test provider's
// HTTPS server.
func (p *TestProvider) CACert() string { return p.caCert }

// SigningKeys returns the test provider's keys used to sign JWTs and its Alg.
func (p *TestProvider) SigningKeys() (crypto.PrivateKey, crypto.PublicKey, Alg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.privKey, p.pubKey, p.alg
}

// SetSigningKeys sets the test provider's keys and alg used to sign JWTs.
func (p *TestProvider) SetSigningKeys(privKey crypto.PrivateKey, pubKey crypto.PublicKey, alg Alg, KeyID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.privKey = privKey
	p.pubKey = pubKey
	p.alg = alg
	p.jwks = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   p.pubKey,
				KeyID: KeyID,
			},
		},
	}
}

func (p *TestProvider) writeJSON(w http.ResponseWriter, out interface{}) error {
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}

// writeImplicitResponse will write the required form data response for an
// implicit flow response to the OIDC authorize endpoint
func (p *TestProvider) writeImplicitResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	const respForm = `
<!DOCTYPE html>
<html lang="en">
<head><title>Submit This Form</title></head>
<body onload="javascript:document.forms[0].submit()">
	<form method="post" action="https://client.example.org/callback">
	<input type="hidden" name="state"
	value="%s"/>
	%s
	</form>
</body>
</html>`
	const tokenField = `<input type="hidden" name="%s" value="%s"/>`
	jwtData := p.issueSignedJWT()
	var respTokens strings.Builder
	if !p.omitAccessToken {
		respTokens.WriteString(fmt.Sprintf(tokenField, "access_token", jwtData))
	}
	if !p.omitIDToken {
		respTokens.WriteString(fmt.Sprintf(tokenField, "id_token", jwtData))
	}
	if _, err := w.Write([]byte(fmt.Sprintf(respForm, p.expectedAuthCode, respTokens.String()))); err != nil {
		return err
	}
	return nil
}

func (p *TestProvider) issueSignedJWT() string {
	stdClaims := jwt.Claims{
		Subject:   p.replySubject,
		Issuer:    p.Addr(),
		NotBefore: jwt.NewNumericDate(p.nowFunc().Add(-p.replyExpiry)),
		Expiry:    jwt.NewNumericDate(p.nowFunc().Add(p.replyExpiry)),
		Audience:  jwt.Audience{p.clientID},
	}
	if len(p.customAudiences) != 0 {
		stdClaims.Audience = append(stdClaims.Audience, p.customAudiences...)
	}

	if p.expectedAuthNonce != "" {
		p.customClaims["nonce"] = p.expectedAuthNonce
	}
	return TestSignJWT(p.t, p.privKey, p.alg, stdClaims, p.customClaims, nil)
}

// writeAuthErrorResponse writes a standard OIDC authentication error response.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError
func (p *TestProvider) writeAuthErrorResponse(w http.ResponseWriter, req *http.Request, errorCode, errorMessage string) {
	qv := req.URL.Query()

	// state and error are required error response parameters
	redirectURI := qv.Get("redirect_uri") +
		"?state=" + url.QueryEscape(qv.Get("state")) +
		"&error=" + url.QueryEscape(errorCode)

	if errorMessage != "" {
		// add optional error response parameter
		redirectURI += "&error_description=" + url.QueryEscape(errorMessage)
	}

	http.Redirect(w, req, redirectURI, http.StatusFound)
}

// writeTokenErrorResponse writes a standard OIDC token error response.
// See: https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
func (p *TestProvider) writeTokenErrorResponse(w http.ResponseWriter, req *http.Request, statusCode int, errorCode, errorMessage string) error {
	body := struct {
		Code string `json:"error"`
		Desc string `json:"error_description,omitempty"`
	}{
		Code: errorCode,
		Desc: errorMessage,
	}

	w.WriteHeader(statusCode)
	return p.writeJSON(w, &body)
}

// ServeHTTP implements the test provider's http.Handler.
func (p *TestProvider) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// define all the endpoints supported
	const (
		openidConfiguration = "/.well-known/openid-configuration"
		authorize           = "/authorize"
		token               = "/token"
		userInfo            = "/userinfo"
		wellKnownJwks       = "/.well-known/jwks.json"
		missingJwks         = "/.well-known/missing-jwks.json"
		invalidJwks         = "/.well-known/invalid-jwks.json"
	)
	p.mu.Lock()
	defer p.mu.Unlock()

	p.t.Helper()
	require := require.New(p.t)

	// set a default Content-Type which will be overridden as needed.
	w.Header().Set("Content-Type", "application/json")

	switch req.URL.Path {
	case openidConfiguration:
		// OIDC Discovery endpoint request
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		reply := struct {
			Issuer           string `json:"issuer"`
			AuthEndpoint     string `json:"authorization_endpoint"`
			TokenEndpoint    string `json:"token_endpoint"`
			JWKSURI          string `json:"jwks_uri"`
			UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
		}{
			Issuer:           p.Addr(),
			AuthEndpoint:     p.Addr() + authorize,
			TokenEndpoint:    p.Addr() + token,
			JWKSURI:          p.Addr() + wellKnownJwks,
			UserinfoEndpoint: p.Addr() + userInfo,
		}
		if p.disableUserInfo {
			reply.UserinfoEndpoint = ""
		}

		err := p.writeJSON(w, &reply)
		require.NoErrorf(err, "%s: internal error: %w", openidConfiguration, err)

		return
	case authorize:
		// Supports both the authorization code and implicit flows
		// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
		if !strutils.StrListContains([]string{"POST", "GET"}, req.Method) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := req.ParseForm()
		require.NoErrorf(err, "%s: internal error: %w", authorize, err)

		respType := req.FormValue("code")
		scopes := req.Form["scope"]

		if respType != "code" {
			p.writeAuthErrorResponse(w, req, "unsupported_response_type", "")
			return
		}
		if !strutils.StrListContains(scopes, "openid") {
			p.writeAuthErrorResponse(w, req, "invalid_scope", "")
			return
		}

		if p.expectedAuthCode == "" {
			p.writeAuthErrorResponse(w, req, "access_denied", "")
			return
		}

		nonce := req.FormValue("nonce")
		if p.expectedAuthNonce != "" && p.expectedAuthNonce != nonce {
			p.writeAuthErrorResponse(w, req, "access_denied", "")
			return
		}

		state := req.FormValue("state")
		if state == "" {
			p.writeAuthErrorResponse(w, req, "invalid_request", "missing state parameter")
			return
		}

		redirectURI := req.FormValue("redirect_uri")
		if redirectURI == "" {
			p.writeAuthErrorResponse(w, req, "invalid_request", "missing redirect_uri parameter")
			return
		}

		if req.FormValue("response_mode") == "form_post" {
			err := p.writeImplicitResponse(w)
			require.NoErrorf(err, "%s: internal error: %w", token, err)
			return
		}

		redirectURI += "?state=" + url.QueryEscape(state) +
			"&code=" + url.QueryEscape(p.expectedAuthCode)

		http.Redirect(w, req, redirectURI, http.StatusFound)

		return

	case wellKnownJwks:
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		err := p.writeJSON(w, p.jwks)
		require.NoErrorf(err, "%s: internal error: %w", wellKnownJwks, err)
		return
	case missingJwks:
		w.WriteHeader(http.StatusNotFound)
		return
	case invalidJwks:
		_, err := w.Write([]byte("It's not a keyset!"))
		require.NoErrorf(err, "%s: internal error: %w", invalidJwks, err)
		return
	case token:
		if req.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		switch {
		case req.FormValue("grant_type") != "authorization_code":
			_ = p.writeTokenErrorResponse(w, req, http.StatusBadRequest, "invalid_request", "bad grant_type")
			return
		case !strutils.StrListContains(p.allowedRedirectURIs, req.FormValue("redirect_uri")):
			_ = p.writeTokenErrorResponse(w, req, http.StatusBadRequest, "invalid_request", "redirect_uri is not allowed")
			return
		case req.FormValue("code") != p.expectedAuthCode:
			_ = p.writeTokenErrorResponse(w, req, http.StatusUnauthorized, "invalid_grant", "unexpected auth code")
			return
		}

		jwtData := p.issueSignedJWT()
		reply := struct {
			AccessToken string `json:"access_token,omitempty"`
			IDToken     string `json:"id_token,omitempty"`
		}{
			AccessToken: jwtData,
			IDToken:     jwtData,
		}
		if p.omitIDToken {
			reply.IDToken = ""
		}
		if p.omitAccessToken {
			reply.AccessToken = ""
		}

		if err := p.writeJSON(w, &reply); err != nil {
			require.NoErrorf(err, "%s: internal error: %w", token, err)
			return
		}
		return
	case userInfo:
		if p.disableUserInfo {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := p.writeJSON(w, p.replyUserinfo); err != nil {
			require.NoErrorf(err, "%s: internal error: %w", userInfo, err)
			return
		}
		return

	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

// httptestNewUnstartedServerWithPort is roughly the same as
// httptest.NewUnstartedServer() but allows the caller to explicitly choose the
// port if desired.
func httptestNewUnstartedServerWithPort(t *testing.T, handler http.Handler, port int) *httptest.Server {
	t.Helper()
	require := require.New(t)
	if port == 0 {
		return httptest.NewUnstartedServer(handler)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	l, err := net.Listen("tcp", addr)
	require.NoError(err)

	return &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
}
