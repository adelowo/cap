package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
)

func CallbackHandler(ctx context.Context, p *oidc.Provider, sc *stateCache, withImplicit bool) (http.HandlerFunc, error) {
	if withImplicit {
		c, err := callback.Implicit(ctx, p, sc, afterCallbackHandler(sc))
		if err != nil {
			return nil, fmt.Errorf("CallbackHandler: %w", err)
		}
		return c, nil
	}
	c, err := callback.AuthCode(ctx, p, sc, afterCallbackHandler(sc))
	if err != nil {
		return nil, fmt.Errorf("CallbackHandler: %w", err)
	}
	return c, nil
}

func successFn(ctx context.Context, sc *stateCache) callback.SuccessResponseFunc {
	return func(stateID string, t oidc.Token, w http.ResponseWriter, req *http.Request) {
		s, err := sc.Read(ctx, stateID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := sc.SetToken(s.ID(), t); err != nil {
			fmt.Fprintf(os.Stderr, "error updating state during successful response: %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect to logged in page
		http.Redirect(w, req, fmt.Sprintf("/success?state=%s", stateID), http.StatusSeeOther)
	}
}

func failedFn(ctx context.Context, sc *stateCache) callback.ErrorResponseFunc {
	const op = "failedFn"
	return func(stateID string, r *callback.AuthenErrorResponse, e error, w http.ResponseWriter, req *http.Request) {
		var responseErr error
		defer func() {
			if _, err := w.Write([]byte(responseErr.Error())); err != nil {
				fmt.Fprintf(os.Stderr, "error writing failed response: %s\n", err)
			}
		}()

		if e != nil {
			fmt.Fprintf(os.Stderr, "callback error: %s\n", e.Error())
			responseErr = e
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r != nil {
			fmt.Fprintf(os.Stderr, "callback error from oidc provider: %s\n", r)
			responseErr = fmt.Errorf("%s: callback error from oidc provider: %s", op, r)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		responseErr = fmt.Errorf("%s: unknown error from callback", op)
	}
}

// afterCallback creates an http.HandlerFunc that is called after the OIDC
// callback.  It also creates channels for successful responses and errors
func afterCallbackHandler(sc *stateCache) http.HandlerFunc {
	const op = "handler"
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		id, ok := callback.StateID(ctx)
		if !ok {
			fmt.Fprintf(os.Stderr, "error getting state id from context: %s\n", ctx)
		}
		t, found := callback.Token(req.Context())
		if found {
			if err := sc.SetToken(id, t); err != nil {
				fmt.Fprintf(os.Stderr, "error updating state during successful response: %s\n", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Redirect to logged in page
			http.Redirect(w, req, fmt.Sprintf("/success?state=%s", id), http.StatusSeeOther)
			return
		}

		var responseErr error
		defer func() {
			if _, err := w.Write([]byte(responseErr.Error())); err != nil {
				fmt.Fprintf(os.Stderr, "error writing failed response: %s\n", err)
			}
		}()
		if e, found := callback.Error(req.Context()); found {
			fmt.Fprintf(os.Stderr, "%s: callback error: %s", op, e.Error())
			responseErr = e
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r, found := callback.ErrorResponse(req.Context()); found {
			responseErr = fmt.Errorf("%s: callback error from oidc provider: %s", op, r)
			fmt.Fprint(os.Stderr, responseErr.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		responseErr = fmt.Errorf("%s: unknown error from callback", op)
	}
}
