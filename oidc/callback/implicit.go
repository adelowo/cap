package callback

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/oidc"
	"golang.org/x/oauth2"
)

// Implicit creates an oidc implicit flow callback handler which
// uses a StateReader to read existing oidc.State(s) via the request's
// oidc "state" parameter as a key for the lookup.
//
// It should be noted that if your OIDC provider supports PKCE, then
// use it over the implicit flow
//
// The SuccessResponseFunc is used to create a response when callback is
// successful.
//
// The ErrorResponseFunc is to create a response when the callback fails.
func Implicit(_ context.Context, p *oidc.Provider, rw StateReader, next http.HandlerFunc) (http.HandlerFunc, error) {
	const op = "callback.Implicit"
	if p == nil {
		return nil, fmt.Errorf("%s: provider is empty: %w", op, oidc.ErrInvalidParameter)
	}
	if rw == nil {
		return nil, fmt.Errorf("%s: state reader is empty: %w", op, oidc.ErrInvalidParameter)
	}
	if next == nil {
		return nil, fmt.Errorf("%s: next http.HandlerFunc is empty: %w", op, oidc.ErrInvalidParameter)
	}
	return func(w http.ResponseWriter, req *http.Request) {
		const op = "callback.Implicit"

		reqState := req.FormValue("state")
		nextCtx := context.WithValue(req.Context(), contextStateID, reqState)

		if err := req.FormValue("error"); err != "" {
			// get parameters from either the body or query parameters.
			// FormValue prioritizes body values, if found
			reqError := &AuthenErrorResponse{
				Error:       err,
				Description: req.FormValue("error_description"),
				Uri:         req.FormValue("error_uri"),
			}
			nextCtx = context.WithValue(nextCtx, contextKeyAuthenErrorResponse, reqError)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		if reqState == "" {
			responseErr := fmt.Errorf("%s: empty state parameter: %w", op, oidc.ErrInvalidParameter)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		state, err := rw.Read(nextCtx, reqState)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to read auth code state: %w", op, err)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		if state == nil {
			// could have expired or it could be invalid... no way to known for
			// sure
			responseErr := fmt.Errorf("%s: auth code state not found: %w", op, oidc.ErrNotFound)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		useImplicit, includeAccessToken := state.ImplicitFlow()
		if !useImplicit {
			responseErr := fmt.Errorf("%s: state (%s) should not be using the implicit flow: %w", op, state.ID(), oidc.ErrInvalidFlow)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		if state.IsExpired() {
			responseErr := fmt.Errorf("%s: authentication state is expired: %w", op, oidc.ErrExpiredState)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		if reqState != state.ID() {
			// the stateReadWriter didn't return the correct state for the key
			// given... this is an internal sort of error on the part of the
			// reader.
			responseErr := fmt.Errorf("%s: authen state (%s) and response state (%s) are not equal: %w", op, state.ID(), reqState, oidc.ErrResponseStateInvalid)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		reqIDToken := oidc.IDToken(req.FormValue("id_token"))
		if _, err := p.VerifyIDToken(nextCtx, reqIDToken, state); err != nil {
			responseErr := fmt.Errorf("%s: unable to verify id_token: %w", op, err)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		var oath2Token *oauth2.Token
		if includeAccessToken {
			reqAccessToken := req.FormValue("access_token")
			if reqAccessToken != "" {
				if _, err := reqIDToken.VerifyAccessToken(oidc.AccessToken(reqAccessToken)); err != nil {
					responseErr := fmt.Errorf("%s: unable to verify access_token: %w", op, err)
					nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
					next.ServeHTTP(w, req.WithContext(nextCtx))
					return
				}
				oath2Token = &oauth2.Token{
					AccessToken: reqAccessToken,
				}
			}
		}

		responseToken, err := oidc.NewToken(oidc.IDToken(reqIDToken), oath2Token)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to create response tokens: %w", op, err)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		nextCtx = context.WithValue(nextCtx, contextToken, responseToken)
		next.ServeHTTP(w, req.WithContext(nextCtx))
	}, nil
}
