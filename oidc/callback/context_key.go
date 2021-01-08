package callback

import (
	"context"

	"github.com/hashicorp/cap/oidc"
)

type contextKey string

func (c contextKey) String() string {
	return "callback context key: " + string(c)
}

var (
	contextStateID                = contextKey("callback-state-id")
	contextToken                  = contextKey("callback-token")
	contextKeyError               = contextKey("callback-error")
	contextKeyAuthenErrorResponse = contextKey("callback-authen-error-response")
)

// StateID returns the state ID and a bool indicating if it was present from a
// context.
func StateID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextStateID).(string)
	return id, ok
}

// Token returns the token and a bool indicating if it was present from a
// context.
func Token(ctx context.Context) (oidc.Token, bool) {
	t, ok := ctx.Value(contextToken).(oidc.Token)
	return t, ok
}

// Token returns the error and a bool indicating if it was present from a
// context.
func Error(ctx context.Context) (error, bool) {
	err, ok := ctx.Value(contextKeyError).(error)
	return err, ok
}

// ErrorResponse returns the error response from the OIDC provider and a bool
// indicating if it was present from a context.
func ErrorResponse(ctx context.Context) (*AuthenErrorResponse, bool) {
	resp, ok := ctx.Value(contextKeyAuthenErrorResponse).(*AuthenErrorResponse)
	return resp, ok
}
