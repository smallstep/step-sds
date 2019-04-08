package sds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"strings"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/x509util"
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
// type Service interface {
// 	Register(s *grpc.Server)
// 	discovery.SecretDiscoveryServiceServer
// }
type Service struct {
	provisioner           *ca.Provisioner
	stopCh                chan struct{}
	authorizedIdentity    string
	authorizedFingerprint string
}

// Config is the configuration used to initialize the SDS Service.
type Config struct {
	AuthorizedIdentity    string            `json:"authorizedIdentity"`
	AuthorizedFingerprint string            `json:"authorizedFingerprint"`
	Provisioner           ProvisionerConfig `json:"provisioner"`
}

// ProvisionerConfig is the configuration used to initialize the provisioner.
type ProvisionerConfig struct {
	Issuer   string `json:"iss"`
	KeyID    string `json:"kid"`
	Password string `json:"password,omitempty"`
	CaURL    string `json:"ca-url"`
	CaRoot   string `json:"root"`
}

// New creates a new sds.Service that will support multiple TLS certificates. It
// will use the given CA provisioner to generate the CA tokens used to sign
// certificates.
func New(c Config) (*Service, error) {
	p, err := ca.NewProvisioner(
		c.Provisioner.Issuer, c.Provisioner.KeyID,
		c.Provisioner.CaURL, c.Provisioner.CaRoot,
		[]byte(c.Provisioner.Password))
	if err != nil {
		return nil, err
	}

	return &Service{
		provisioner:           p,
		stopCh:                make(chan struct{}),
		authorizedIdentity:    c.AuthorizedIdentity,
		authorizedFingerprint: c.AuthorizedFingerprint,
	}, nil
}

// Stop stops the current service.
func (srv *Service) Stop() error {
	close(srv.stopCh)
	return nil
}

// Register registers the sds.Service into the given gRPC server.
func (srv *Service) Register(s *grpc.Server) {
	discovery.RegisterSecretDiscoveryServiceServer(s, srv)
}

// StreamSecrets implements the gRPC SecretDiscoveryService service and returns
// a stream of TLS certificates.
func (srv *Service) StreamSecrets(sds discovery.SecretDiscoveryService_StreamSecretsServer) (err error) {
	var rnw renewer

	errCh := make(chan error)
	reqCh := make(chan *api.DiscoveryRequest)

	go func() {
		for {
			r, err := sds.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if err := srv.validateRequest(sds.Context(), r); err != nil {
				errCh <- err
				return
			}
			reqCh <- r
		}
	}()

	var cert *tls.Certificate
	var roots []*x509.Certificate
	var ch chan *certificate
	var nonce, versionInfo string
	var req *api.DiscoveryRequest

	for {
		select {
		case r := <-reqCh:
			log.Println("StreamSecrets: ", r.String())
			// Validations
			switch {
			case r.ErrorDetail != nil:
				log.Printf("ErrorDetail received: %v\n", r.ErrorDetail)
				continue
			case nonce != r.ResponseNonce:
				log.Printf("ResponseNonce unexpected, wants %s, got %s\n", nonce, r.ResponseNonce)
				continue
			case r.VersionInfo == "": // initial request
				versionInfo = srv.versionInfo()
			case r.VersionInfo == versionInfo: // ACK
				continue
			}

			req = r
			subject, ok := getSubject(req)
			if ok {
				token, err := srv.provisioner.Token(subject)
				if err != nil {
					return err
				}
				cr, err := newCertRnewer(token)
				if err != nil {
					return err
				}
				defer cr.Stop()
				rnw = cr
			} else {
				token, err := srv.provisioner.Token("fake-root-subject")
				if err != nil {
					return err
				}
				rr, err := newRootRnewer(token)
				if err != nil {
					return err
				}
				defer rr.Stop()
				rnw = rr
			}

			ch = rnw.RenewChannel()
			cert = rnw.ServerCertificate()
			roots = rnw.RootCertificates()
		case certs := <-ch:
			versionInfo = srv.versionInfo()
			cert, roots = certs.Server, certs.Roots
		case err := <-errCh:
			if err == io.EOF {
				return nil
			}
			return err
		case <-srv.stopCh:
			return nil
		}

		// Send certificates
		dr, err := getDiscoveryResponse(req, versionInfo, cert, roots)
		if err != nil {
			return err
		}
		nonce = dr.Nonce
		if err := sds.Send(dr); err != nil {
			return err
		}
	}
}

// FetchSecrets implements gRPC SecretDiscoveryService service and returns one TLS certificate.
func (srv *Service) FetchSecrets(ctx context.Context, r *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	log.Println("FetchSecrets: ", r.String())
	if err := srv.validateRequest(ctx, r); err != nil {
		return nil, err
	}

	subject, ok := getSubject(r)
	if !ok {
		return nil, errors.Errorf("DiscoveryRequest does not contain a valid subject: %s", r.String())
	}

	versionInfo := time.Now().UTC().Format(time.RFC3339)
	token, err := srv.provisioner.Token(subject)
	if err != nil {
		return nil, err
	}
	cr, err := newCertRnewer(token)
	if err != nil {
		return nil, err
	}
	defer cr.Stop()

	cert := cr.ServerCertificate()
	roots := cr.RootCertificates()
	return getDiscoveryResponse(r, versionInfo, cert, roots)
}

func (srv *Service) validateRequest(ctx context.Context, r *api.DiscoveryRequest) error {
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
