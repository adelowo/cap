package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/cap/oidc"
)

func LoginHandler(ctx context.Context, p *oidc.Provider, sc *stateCache, timeout time.Duration, redirectURL string, withImplicit bool) http.HandlerFunc {
	var urlOption oidc.Option
	if withImplicit {
		urlOption = oidc.WithImplicitFlow()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := oidc.NewState(timeout, redirectURL)
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			return
		}
		sc.Add(s)

		authURL, err := p.AuthURL(context.Background(), s, urlOption)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting auth url: %s", err)
			return
		}
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}