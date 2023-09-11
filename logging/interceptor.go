package logging

import (
	"context"
	"crypto/tls"
	"path"
	"strings"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/sirupsen/logrus"
)

type interceptorType int

const (
	unaryType interceptorType = iota
	streamType
)

// String implements the fmt.Stringer interface.
func (t interceptorType) String() string {
	switch t {
	case unaryType:
		return "unary"
	case streamType:
		return "stream"
	default:
		return ""
	}
}

// UnaryServerInterceptor returns a new unary server interceptors that adds logrus.Entry to the context.
func UnaryServerInterceptor(logger *Logger) grpc.UnaryServerInterceptor {
	loggerImpl := logger.GetImpl()
	traceHeader := strings.ToLower(logger.GetTraceHeader())
	timeFormat := logger.GetTimeFormat()

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var requestID string
		t1 := time.Now()

		// Get or set request id
		ctx, requestID = getRequestID(ctx, traceHeader)
		// Add request context to log each stream message
		ctx = newEntryForCall(ctx, logrus.NewEntry(loggerImpl), info.FullMethod, t1.Format(timeFormat))

		// Call handler
		resp, err := handler(ctx, req)
		duration := time.Since(t1)
		startTime := t1.Format(timeFormat)

		// Write log
		writeLog(ctx, loggerImpl, unaryType, requestID, info.FullMethod, startTime, duration, err)

		return resp, err
	}
}

// StreamServerInterceptor returns a new streaming server interceptor that adds logrus.Entry to the context.
func StreamServerInterceptor(logger *Logger) grpc.StreamServerInterceptor {
	loggerImpl := logger.GetImpl()
	traceHeader := strings.ToLower(logger.GetTraceHeader())
	timeFormat := logger.GetTimeFormat()

	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		t1 := time.Now()

		// Get or set request id
		ctx, requestID := getRequestID(stream.Context(), traceHeader)
		// Add request context to log each stream message
		ctx = newEntryForCall(ctx, logrus.NewEntry(loggerImpl), info.FullMethod, t1.Format(timeFormat))

		// Wrap stream with the new context
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = ctx

		// Call handler
		err := handler(srv, wrapped)
		duration := time.Since(t1)

		startTime := t1.Format(timeFormat)

		// Write log
		writeLog(ctx, loggerImpl, streamType, requestID, info.FullMethod, startTime, duration, err)

		return err
	}
}

// getRequestID get the requestID from the context metadata or generates a new
// one and appends it to the context.
func getRequestID(ctx context.Context, traceHeader string) (context.Context, string) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v, ok := md[traceHeader]; ok {
			return WithRequestID(ctx, v[0]), v[0]
		}
		requestID := NewRequestID()
		newMD := metadata.Join(md, metadata.Pairs(traceHeader, requestID))
		return WithRequestID(metadata.NewIncomingContext(ctx, newMD), requestID), requestID
	}

	requestID := NewRequestID()
	newMD := metadata.Pairs(traceHeader, requestID)
	return WithRequestID(metadata.NewIncomingContext(ctx, newMD), requestID), requestID
}

func newEntryForCall(ctx context.Context, entry *logrus.Entry, fullMethodString, startTime string) context.Context {
	var pkg string
	service := path.Dir(fullMethodString)[1:]
	method := path.Base(fullMethodString)
	parts := strings.Split(service, ".")
	if l := len(parts); l > 1 {
		pkg = strings.Join(parts[:l-1], ".")
		service = parts[l-1]
	}
	callLog := entry.WithFields(
		logrus.Fields{
			"system":          "grpc",
			"span.kind":       "server",
			"grpc.package":    pkg,
			"grpc.service":    service,
			"grpc.method":     method,
			"grpc.start_time": startTime,
		})

	if d, ok := ctx.Deadline(); ok {
		callLog = callLog.WithFields(
			logrus.Fields{
				"grpc.request.deadline": d.Format(time.RFC3339),
			})
	}
	return WithRequestEntry(ctx, callLog)
}

//nolint:revive // despite unused inputs, they serve as documentation.
func writeLog(ctx context.Context, _ *logrus.Logger, typ interceptorType, requestID, fullMethod, startTime string, duration time.Duration, grpcErr error) {
	code := status.Code(grpcErr)

	// Get common fields
	entry := GetRequestEntry(ctx)

	// Add or overwrite fields
	fields := logrus.Fields{
		"grpc.code":        code.String(),
		"grpc.request.id":  requestID,
		"grpc.start_time":  startTime,
		"grpc.duration":    duration.String(),
		"grpc.duration-ns": duration.Nanoseconds(),
	}
	if pr, ok := peer.FromContext(ctx); ok {
		fields["peer.address"] = pr.Addr.String()
		if s, ok := getPeerIdentity(pr); ok {
			fields["peer.identity"] = s
		}
	}
	if grpcErr != nil {
		fields[ErrorKey] = grpcErr
	}

	entry = entry.WithFields(fields)

	var msg string
	switch typ {
	case unaryType:
		msg = "finished unary call with code " + code.String()
	case streamType:
		msg = "finished streaming call with code " + code.String()
	}

	switch codeToLevel(code) {
	case logrus.InfoLevel:
		entry.Info(msg)
	case logrus.WarnLevel:
		entry.Warn(msg)
	case logrus.ErrorLevel:
		entry.Error(msg)
	default:
		entry.Error(msg)
	}
}

// codeToLevel returns the log level to use for a given gRPC return code.
func codeToLevel(code codes.Code) logrus.Level {
	switch code {
	case codes.OK:
		return logrus.InfoLevel
	case codes.Canceled:
		return logrus.InfoLevel
	case codes.Unknown:
		return logrus.ErrorLevel
	case codes.InvalidArgument:
		return logrus.InfoLevel
	case codes.DeadlineExceeded:
		return logrus.WarnLevel
	case codes.NotFound:
		return logrus.InfoLevel
	case codes.AlreadyExists:
		return logrus.InfoLevel
	case codes.PermissionDenied:
		return logrus.WarnLevel
	case codes.Unauthenticated:
		return logrus.InfoLevel
	case codes.ResourceExhausted:
		return logrus.WarnLevel
	case codes.FailedPrecondition:
		return logrus.WarnLevel
	case codes.Aborted:
		return logrus.WarnLevel
	case codes.OutOfRange:
		return logrus.WarnLevel
	case codes.Unimplemented:
		return logrus.ErrorLevel
	case codes.Internal:
		return logrus.ErrorLevel
	case codes.Unavailable:
		return logrus.WarnLevel
	case codes.DataLoss:
		return logrus.ErrorLevel
	default:
		return logrus.ErrorLevel
	}
}

func getPeerIdentity(p *peer.Peer) (string, bool) {
	if p.AuthInfo == nil {
		return "", false
	}
	if p.AuthInfo.AuthType() == "tls" {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return getCommonName(tlsInfo.State)
		}
	}

	return "", false
}

func getCommonName(cs tls.ConnectionState) (string, bool) {
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0] == nil {
		return "", false
	}
	return cs.PeerCertificates[0].Subject.CommonName, true
}
