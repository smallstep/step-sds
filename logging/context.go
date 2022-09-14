package logging

import (
	"context"
	"io"
	"net/http"

	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
)

type key int

const (
	// RequestIDKey is the context key that should store the request identifier.
	RequestIDKey key = iota
	// RequestEntryKey is the context key that should store information about the current request.
	RequestEntryKey
)

var nullLogger = &logrus.Logger{
	Out:       io.Discard,
	Formatter: new(logrus.TextFormatter),
	Hooks:     make(logrus.LevelHooks),
	Level:     logrus.PanicLevel,
}

// NewRequestID creates a new request id using github.com/rs/xid.
func NewRequestID() string {
	return xid.New().String()
}

// RequestID returns a new middleware that gets the given header and sets it
// in the context so it can be written in the logger. If the header does not
// exists or it's the empty string, it uses github.com/rs/xid to create a new
// one.
func RequestID(headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, req *http.Request) {
			requestID := req.Header.Get(headerName)
			if requestID == "" {
				requestID = NewRequestID()
				req.Header.Set(headerName, requestID)
			}

			ctx := WithRequestID(req.Context(), requestID)
			next.ServeHTTP(w, req.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// WithRequestID returns a new context with the given requestID added to the
// context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID returns the request id from the context if it exists.
func GetRequestID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(RequestIDKey).(string)
	return v, ok
}

// WithRequestEntry creates a new context with the given logrus entry.
func WithRequestEntry(ctx context.Context, entry *logrus.Entry) context.Context {
	return context.WithValue(ctx, RequestEntryKey, entry)
}

// GetRequestEntry returns the logrus entry of the request.
func GetRequestEntry(ctx context.Context) *logrus.Entry {
	e, ok := ctx.Value(RequestEntryKey).(*logrus.Entry)
	if !ok || e == nil {
		return logrus.NewEntry(nullLogger)
	}
	return e
}

// AddFields adds logrus fields to the logger.
func AddFields(ctx context.Context, fields Fields) {
	e, ok := ctx.Value(RequestEntryKey).(*logrus.Entry)
	if !ok || e == nil {
		return
	}
	for k, v := range fields {
		e.Data[k] = v
	}
}
