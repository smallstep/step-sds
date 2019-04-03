package sds

import (
	"context"
	"log"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"google.golang.org/grpc"
)

// VersionInfo is the version sent to the Envoy server in the discovery
// responses.
var VersionInfo = "0.0.1"

// Identifier is the identifier of the secret discovery service.
var Identifier = "Smallstep SDS/0000000-dev"

// ValidationContextName is the name used as a resource name for the validation context.
var ValidationContextName = "trusted_ca"

// ValidationContextAltName is an alternative name used as a resource name for
// the validation context.
var ValidationContextAltName = "validation_context"

// Service is the interface that an Envoy secret discovery service (SDS) has to
// implement. They server TLS certificates to Envoy using gRPC.
// type Service interface {
// 	Register(s *grpc.Server)
// 	discovery.SecretDiscoveryServiceServer
// }
type Service struct {
	provisioner *ca.Provisioner
}

// New creates a new sds.Service that will support multiple TLS certificates. It
// will use the given CA provisioner to generate the CA tokens used to sign
// certificates.
func New(iss, kid, caURL, caRoot string, password []byte) (*Service, error) {
	p, err := ca.NewProvisioner(iss, kid, caURL, caRoot, password)
	if err != nil {
		return nil, err
	}

	return &Service{
		provisioner: p,
	}, nil
}

// Stop stops the current service.
func (srv *Service) Stop() error {
	return nil
}

// Register registers the sds.Service into the given gRPC server.
func (srv *Service) Register(s *grpc.Server) {
	discovery.RegisterSecretDiscoveryServiceServer(s, srv)
}

// StreamSecrets implements the gRPC SecretDiscoveryService service and returns
// a stream of TLS certificates.
func (srv *Service) StreamSecrets(sds discovery.SecretDiscoveryService_StreamSecretsServer) (err error) {
	r, err := sds.Recv()
	if err != nil {
		return err
	}

	log.Println("StreamSecrets: ", r.String())

	subject, ok := getSubject(r)
	if !ok {
		// FIXME: trusted ca flow
		subject = r.ResourceNames[0]
		// return errors.Errorf("DiscoveryRequest does not contain a valid subject: %s", r.String())
	}
	token, err := srv.provisioner.Token(subject)
	if err != nil {
		return err
	}
	cr, err := newCertRnewer(token)
	if err != nil {
		return err
	}
	defer cr.Stop()

	ch := cr.RenewChannel()
	cert := cr.ServerCertificate()
	roots := cr.RootCertificates()

	for {
		dr, err := getDiscoveryResponse(r, cert, roots)
		if err != nil {
			return err
		}
		err = sds.Send(dr)
		if err != nil {
			return err
		}
		certs := <-ch
		cert, roots = certs.Server, certs.Roots
	}
}

// FetchSecrets implements gRPC SecretDiscoveryService service and returns one TLS certificate.
func (srv *Service) FetchSecrets(ctx context.Context, r *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	log.Println("FetchSecrets: ", r.String())

	subject, ok := getSubject(r)
	if !ok {
		return nil, errors.Errorf("DiscoveryRequest does not contain a valid subject: %s", r.String())
	}

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
	return getDiscoveryResponse(r, cert, roots)
}
