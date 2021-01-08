package callback

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

// AuthCode creates an oidc authorization code callback handler which
// uses a StateReader to read existing oidc.State(s) via the request's
// oidc "state" parameter as a key for the lookup.  In additional to the
// typical authorization code flow, it also handles the authorization code flow
// with PKCE.
//
// AuthCode sets the following context values before calling the next http
// handler:
// * StateID
// * Token
// * ErrorResponse
// * Error

//
// The SuccessResponseFunc is used to create a response when callback is
// successful.
//
// The ErrorResponseFunc is to create a response when the callback fails.
func AuthCode(_ context.Context, p *oidc.Provider, rw StateReader, next http.HandlerFunc) (http.HandlerFunc, error) {
	const op = "callback.AuthCode"
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
		const op = "callback.AuthCodeState"

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

		// get parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		reqCode := req.FormValue("code")

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
			responseErr := fmt.Errorf("%s: authentication state and response state are not equal: %w", op, oidc.ErrResponseStateInvalid)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		if useImplicit, _ := state.ImplicitFlow(); useImplicit {
			responseErr := fmt.Errorf("%s: state (%s) should not be using the authorization code flow: %w", op, state.ID(), oidc.ErrInvalidFlow)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}

		responseToken, err := p.Exchange(nextCtx, state, reqState, reqCode)
		if err != nil {
			responseErr := fmt.Errorf("%s: unable to exchange authorization code: %w", op, err)
			nextCtx = context.WithValue(nextCtx, contextKeyError, responseErr)
			next.ServeHTTP(w, req.WithContext(nextCtx))
			return
		}
		nextCtx = context.WithValue(nextCtx, contextToken, responseToken)
		next.ServeHTTP(w, req.WithContext(nextCtx))
	}, nil
}
