package api

import (
	"context"
	"net/http"

	"github.com/yourorg/endpointguard/server/internal/auth"
)

type ctxKey int

const sessionCtxKey ctxKey = iota

func withSession(r *http.Request, sess auth.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess))
}

func sessionFromRequest(r *http.Request) (auth.Session, bool) {
	sess, ok := r.Context().Value(sessionCtxKey).(auth.Session)
	return sess, ok
}
