package logging

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// defaultTraceIdHeader is the default header used as a trace id.
const defaultTraceIDHeader = "X-Smallstep-Id"

// ErrorKey defines the key used to log errors.
var ErrorKey = logrus.ErrorKey

// Fields is an alias of logrus.Fields.
type Fields = logrus.Fields

// Logger is an alias of logrus.Logger.
type Logger struct {
	*logrus.Logger
	name        string
	traceHeader string
	timeFormat  string
}

// loggerConfig represents the configuration options for the logger.
type loggerConfig struct {
	Format      string `json:"format"`
	TraceHeader string `json:"traceHeader"`
	TimeFormat  string `json:"timeFormat"`
}

// New initializes the logger with the given options.
func New(name string, raw json.RawMessage) (*Logger, error) {
	var config loggerConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling logging attribute")
	}

	var formatter logrus.Formatter
	switch strings.ToLower(config.Format) {
	case "", "text":
	case "json":
		formatter = new(logrus.JSONFormatter)
	default:
		return nil, errors.Errorf("unsupported logger.format '%s'", config.Format)
	}

	logger := &Logger{
		Logger:      logrus.New(),
		name:        name,
		traceHeader: config.TraceHeader,
		timeFormat:  config.TimeFormat,
	}
	if formatter != nil {
		logger.Formatter = formatter
	}
	return logger, nil
}

// GetImpl returns the real implementation of the logger.
func (l *Logger) GetImpl() *logrus.Logger {
	return l.Logger
}

// GetTraceHeader returns the trace header configured
func (l *Logger) GetTraceHeader() string {
	if l.traceHeader == "" {
		return defaultTraceIDHeader
	}
	return l.traceHeader
}

// GetTimeFormat return the string to format the time.
func (l *Logger) GetTimeFormat() string {
	if l.timeFormat == "" {
		return time.RFC3339
	}
	return l.timeFormat
}
