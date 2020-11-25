package oidc

import (
	"context"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// AuthCodeProvider provides integration with a provider using the authorization
// code flow.
type AuthCodeProvider struct {
	config   *ProviderConfig
	provider *oidc.Provider

	mu sync.Mutex

	// backgroundCtx is the context used by the provider for background
	// activities like: refreshing JWKs ket sets, refreshing tokens, etc
	backgroundCtx context.Context

	// backgroundCtxCancel is used to cancel any background activities running
	// in spawned go routines.
	backgroundCtxCancel context.CancelFunc
}

// NewAuthCodeProvider creates and initializes a Provider for the OIDC
// authorization code flow.  Intializing the the provider, includes making an
// http request to the provider's issuer.
//
//	See AuthCodeProvider.Stop()
//	See NewProviderConfig() to create a ProviderConfig.
func NewAuthCodeProvider(c *ProviderConfig, opts ...Option) (*AuthCodeProvider, error) {
	const op = "authcode.NewProvider"
	if c == nil {
		return nil, NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("provider config is nil"))
	}
	if err := c.Validate(); err != nil {
		return nil, WrapError(err, WithOp(op), WithKind(ErrParameterViolation), WithMsg("provider config is invalid"), WithWrap(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	// initializing the AuthCodeProvider with it's background ctx/cancel will
	// allow us to use p.Stop() to release any resources when returning errors
	// from this function.
	p := &AuthCodeProvider{
		config:              c,
		backgroundCtx:       ctx,
		backgroundCtxCancel: cancel,
	}

	client, err := c.HttpClient()
	if err != nil {
		p.Stop() // release the backgroundCtxCancel resources
		return nil, WrapError(err, WithOp(op), WithKind(ErrInternal), WithMsg("unable create http client"))
	}

	provider, err := oidc.NewProvider(HttpClientContext(p.backgroundCtx, client), c.Issuer) // makes http req to issuer for discovery
	if err != nil {
		p.Stop() // release the backgroundCtxCancel resources
		// we don't know what's causing the problem, so we won't classify the
		// error with a Kind
		return nil, NewError(ErrInvalidIssuer, WithOp(op), WithMsg("unable to create provider"), WithWrap(err))
	}
	p.provider = provider

	return p, nil
}

// Stop the provider's background resources and must be called for every
// AuthCodeProvider created
func (p *AuthCodeProvider) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.backgroundCtxCancel != nil {
		p.backgroundCtxCancel()
		p.backgroundCtxCancel = nil
	}
}

// AuthURL will generate a URL the caller can use to kick off an OIDC
// authorization code flow with an IdP.  The redirectURL is the URL the IdP
// should use as a redirect after the authentication/authorization is completed
// by the user. The authenState must contain a unique Id and Nonce (they cannot be
// equal) which will be used during the OIDC flow to prevent CSRF and replay
// attacks (see the oidc spec for specifics). The authenState must also contain
// a redirectURL that will handle the IdP redirect and has been configured as a
// valid redirect URL for the IdP.
//
// 	See NewState() to create an authentication state with a valid Id and Nonce.
func (p *AuthCodeProvider) AuthURL(ctx context.Context, authenState State, opts ...Option) (url string, e error) {
	const op = "AuthCodeProvider.AuthURL"
	if authenState.Id == authenState.Nonce {
		return "", NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("state id and nonce cannot be equal"))
	}
	if authenState.RedirectURL == "" {
		return "", NewError(ErrInvalidParameter, WithOp(op), WithKind(ErrParameterViolation), WithMsg("redirectURL is empty"))
	}
	// Add the "openid" scope, which is a required scope for oidc flows
	scopes := append([]string{oidc.ScopeOpenID}, p.config.Scopes...)

	// Configure an OpenID Connect aware OAuth2 client
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientId,
		ClientSecret: p.config.ClientSecret,
		RedirectURL:  authenState.RedirectURL,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       scopes,
	}
	authCodeOpts := []oauth2.AuthCodeOption{
		oidc.Nonce(authenState.Nonce),
	}
	return oauth2Config.AuthCodeURL(authenState.Id, authCodeOpts...), nil
}

func (p *AuthCodeProvider) Exchange(ctx context.Context, authenState State, responseState string, responseCode string) (*Token, error) {
	const op = "AuthCodeProvider.Exchange"
	if p.config == nil {
		return nil, NewError(ErrNilParameter, WithOp(op), WithKind(ErrInternal), WithMsg("provider config is nil"))
	}
	if authenState.IsExpired() {
		return nil, NewError(ErrExpiredState, WithOp(op), WithKind(ErrParameterViolation), WithMsg("authentication state is expired"))
	}
	client, err := p.config.HttpClient()
	if err != nil {
		return nil, WrapError(http.ErrBodyReadAfterClose, WithOp(op), WithKind(ErrInternal), WithMsg("unable to create http client"))
	}

	exchangeCtx := HttpClientContext(ctx, client)

	var oauth2Config = oauth2.Config{
		ClientID:     p.config.ClientId,
		ClientSecret: p.config.ClientSecret,
		RedirectURL:  authenState.RedirectURL,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	oauth2Token, err := oauth2Config.Exchange(exchangeCtx, responseCode)
	if err != nil {
		return nil, NewError(ErrRelyPartyAuthenFailed, WithOp(op), WithKind(ErrInternal), WithMsg("unable to exchange auth code with provider"), WithWrap(err))
	}
	t := &Token{
		RefreshToken: oauth2Token.RefreshToken,
		AccessToken:  oauth2Token.AccessToken,
		Expiry:       oauth2Token.Expiry,
	}
	idToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, NewError(ErrMissingIdToken, WithOp(op), WithKind(ErrInternal), WithMsg("id_token is missing from auth code exchange"), WithWrap(err))
	}
	t.IdToken = idToken

	if err := p.VerifyIdToken(ctx, idToken, authenState.Nonce); err != nil {
		return nil, NewError(ErrIdTokenVerificationFailed, WithOp(op), WithKind(ErrInternal), WithMsg("id_token failed verification"), WithWrap(err))
	}

	t.IdToken = idToken
	return t, nil
}

func (p *AuthCodeProvider) VerifyIdToken(ctx context.Context, idToken, nonce string) error {
	panic("TODO")
}

func (p *AuthCodeProvider) UserInfoClaims(ctx context.Context, t *Token) (map[string]interface{}, error) {
	panic("TODO")
}