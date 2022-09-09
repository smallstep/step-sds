package sds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/step-sds/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Identifier is the identifier of the secret discovery service.
var Identifier = "Smallstep SDS/0000000-dev"

// ValidationContextName is the name used as a resource name for the validation context.
var ValidationContextName = "trusted_ca"

// ValidationContextAltName is an alternative name used as a resource name for
// the validation context.
var ValidationContextAltName = "validation_context"

// ValidationContextRenewPeriod is the default period to check for new roots.
var ValidationContextRenewPeriod = 8 * time.Hour

// Service is the interface that an Envoy secret discovery service (SDS) has to
// implement. They server TLS certificates to Envoy using gRPC.
//
//	type Service interface {
//		Register(s *grpc.Server)
//		discovery.SecretDiscoveryServiceServer
//	}
type Service struct {
	provisioner           *ca.Provisioner
	stopCh                chan struct{}
	authorizedIdentity    string
	authorizedFingerprint string
	isTCP                 bool
	logger                *logging.Logger
}

// New creates a new sds.Service that will support multiple TLS certificates. It
// will use the given CA provisioner to generate the CA tokens used to sign
// certificates.
func New(c Config) (*Service, error) {
	p, err := ca.NewProvisioner(
		c.Provisioner.Issuer, c.Provisioner.KeyID,
		c.Provisioner.CaURL, []byte(c.Provisioner.Password),
		ca.WithRootFile(c.Provisioner.CaRoot))
	if err != nil {
		return nil, err
	}

	logger, err := logging.New("step-sds", c.Logger)
	if err != nil {
		return nil, err
	}

	return &Service{
		provisioner:           p,
		stopCh:                make(chan struct{}),
		authorizedIdentity:    c.AuthorizedIdentity,
		authorizedFingerprint: c.AuthorizedFingerprint,
		isTCP:                 c.IsTCP(),
		logger:                logger,
	}, nil
}

// Stop stops the current service.
func (srv *Service) Stop() error {
	close(srv.stopCh)
	return nil
}

// Register registers the sds.Service into the given gRPC server.
func (srv *Service) Register(s *grpc.Server) {
	secret.RegisterSecretDiscoveryServiceServer(s, srv)
}

func (srv *Service) DeltaSecrets(sds secret.SecretDiscoveryService_DeltaSecretsServer) (err error) {
	return errors.New("DeltaSecretsServer not implemented")
}

// StreamSecrets implements the gRPC SecretDiscoveryService service and returns
// a stream of TLS certificates.
func (srv *Service) StreamSecrets(sds secret.SecretDiscoveryService_StreamSecretsServer) (err error) {
	ctx := sds.Context()
	errCh := make(chan error)
	reqCh := make(chan *discovery.DiscoveryRequest)

	go func() {
		for {
			r, err := sds.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if err := srv.validateRequest(ctx, r); err != nil {
				errCh <- err
				return
			}
			reqCh <- r
		}
	}()

	var t1 time.Time
	var certs []*tls.Certificate
	var roots []*x509.Certificate
	var ch chan secrets
	var nonce, versionInfo string
	var req *discovery.DiscoveryRequest
	var isRenewal bool

	for {
		select {
		case r := <-reqCh:
			t1 = time.Now()
			isRenewal = false

			// Validations
			if r.ErrorDetail != nil {
				srv.logRequest(ctx, r, "NACK", t1, nil)
				continue
			}
			// Do not validate nonce/version if we're restarting the server
			if req != nil {
				switch {
				case nonce != r.ResponseNonce:
					srv.logRequest(ctx, r, "Invalid responseNonce", t1, fmt.Errorf("invalid responseNonce"))
					continue
				case r.VersionInfo == "": // initial request
					versionInfo = srv.versionInfo()
				case r.VersionInfo == versionInfo: // ACK
					srv.logRequest(ctx, r, "ACK", t1, nil)
					continue
				default: // it should not go here
					versionInfo = srv.versionInfo()
				}
			} else {
				versionInfo = srv.versionInfo()
			}

			req = r

			var tokens []string
			for _, name := range req.ResourceNames {
				token, err := srv.provisioner.Token(name)
				if err != nil {
					srv.logRequest(ctx, r, "Error generating token", t1, err)
					return err
				}
				tokens = append(tokens, token)
			}

			sr, err := newSecretRenewer(tokens)
			if err != nil {
				srv.logRequest(ctx, r, "Error creating renewer", t1, err)
				return err
			}
			defer sr.Stop()

			ch = sr.RenewChannel()
			secs := sr.Secrets()
			certs, roots = secs.Certificates, secs.Roots
		case secs := <-ch:
			t1 = time.Now()
			isRenewal = true
			versionInfo = srv.versionInfo()
			certs, roots = secs.Certificates, secs.Roots
		case err := <-errCh:
			t1 = time.Now()
			if err == io.EOF {
				return nil
			}
			srv.logRequest(ctx, nil, "Recv failed", t1, err)
			return err
		case <-srv.stopCh:
			return nil
		}

		// Send certificates
		dr, err := getDiscoveryResponse(req, versionInfo, certs, roots)
		if err != nil {
			srv.logRequest(ctx, req, "Creation of DiscoveryResponse failed", t1, err)
			return err
		}
		if err := sds.Send(dr); err != nil {
			srv.logRequest(ctx, req, "Send failed", t1, err)
			return err
		}

		nonce = dr.Nonce
		extra := logging.Fields{
			"nonce": nonce,
		}

		if len(certs) > 0 {
			if isRenewal {
				srv.logRequest(ctx, req, "Certificate renewed", t1, err, extra)
			} else {
				srv.logRequest(ctx, req, "Certificate sent", t1, err, extra)
			}
		} else {
			srv.logRequest(ctx, req, "Trusted CA sent", t1, err, extra)
		}
	}
}

// FetchSecrets implements gRPC SecretDiscoveryService service and returns one TLS certificate.
func (srv *Service) FetchSecrets(ctx context.Context, r *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error) {
	srv.addRequestToContext(ctx, r)
	if err := srv.validateRequest(ctx, r); err != nil {
		return nil, err
	}

	var tokens []string
	for _, name := range r.ResourceNames {
		token, err := srv.provisioner.Token(name)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}

	sr, err := newSecretRenewer(tokens)
	if err != nil {
		return nil, err
	}
	defer sr.Stop()

	secs := sr.Secrets()
	certs, roots := secs.Certificates, secs.Roots
	versionInfo := time.Now().UTC().Format(time.RFC3339)

	return getDiscoveryResponse(r, versionInfo, certs, roots)
}

func (srv *Service) validateRequest(ctx context.Context, r *discovery.DiscoveryRequest) error {
	if !srv.isTCP {
		return nil
	}

	// TLS validation
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Errorf(codes.Internal, "failed to obtain peer for request")
	}

	var cs *tls.ConnectionState
	switch tlsInfo := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		cs = &tlsInfo.State
	case *credentials.TLSInfo:
		cs = &tlsInfo.State
	default:
		return status.Errorf(codes.Internal, "failed to obtain connection state for request")
	}

	if len(cs.PeerCertificates) == 0 {
		return status.Errorf(codes.PermissionDenied, "missing peer certificate")
	}

	if srv.authorizedIdentity != "" {
		cn := cs.PeerCertificates[0].Subject.CommonName
		if !strings.EqualFold(cn, srv.authorizedIdentity) {
			return status.Errorf(codes.PermissionDenied, "certificate common name %s is not authorized", cn)
		}
	}

	if srv.authorizedFingerprint != "" {
		fp := x509util.Fingerprint(cs.PeerCertificates[0])
		if !strings.EqualFold(fp, srv.authorizedFingerprint) {
			return status.Errorf(codes.PermissionDenied, "certificate fingerprint %s is not authorized", fp)
		}
	}

	return nil
}

func (srv *Service) versionInfo() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (srv *Service) logRequest(ctx context.Context, r *discovery.DiscoveryRequest, msg string, start time.Time, err error, extra ...logging.Fields) {
	duration := time.Since(start)
	entry := logging.GetRequestEntry(ctx)

	// overwrite start_time
	entry.Data["grpc.start_time"] = start.Format(srv.logger.GetTimeFormat())
	entry.Data["grpc.duration"] = duration.String()
	entry.Data["grpc.duration-ns"] = duration.Nanoseconds()
	if r != nil {
		entry.Data["versionInfo"] = r.VersionInfo
		entry.Data["resourceNames"] = r.ResourceNames
		entry.Data["responseNonce"] = r.ResponseNonce
		if r.Node != nil {
			entry.Data["node"] = r.Node.Id
			entry.Data["cluster"] = r.Node.Cluster
		}
		if r.ErrorDetail != nil {
			entry.Data["code"] = r.ErrorDetail.Code
			entry.Data[logging.ErrorKey] = r.ErrorDetail.Message
		}
	}
	var infoLevel bool
	if len(extra) > 0 {
		infoLevel = true
		for _, fields := range extra {
			for k, v := range fields {
				entry.Data[k] = v
			}
		}
	}
	if err != nil {
		entry.Data[logging.ErrorKey] = err
	}

	if err != nil || (r != nil && r.ErrorDetail != nil) {
		entry.Error(msg)
	} else if infoLevel {
		entry.Info(msg)
	} else {
		entry.Debug(msg)
	}
}

func (srv *Service) addRequestToContext(ctx context.Context, r *discovery.DiscoveryRequest) {
	var fields logging.Fields
	if r != nil {
		fields = logging.Fields{
			"versionInfo":   r.VersionInfo,
			"resourceNames": r.ResourceNames,
			"responseNonce": r.ResponseNonce,
		}
		if r.Node != nil {
			fields["node"] = r.Node.Id
			fields["cluster"] = r.Node.Cluster
		}
		if r.ErrorDetail != nil {
			fields["code"] = r.ErrorDetail.Code
			fields[logging.ErrorKey] = r.ErrorDetail.Message
		}
	}
	logging.AddFields(ctx, fields)
}
