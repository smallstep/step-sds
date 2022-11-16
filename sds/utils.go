package sds

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const secretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// isValidationContext returns if the given name is one of the predefined
// validation context names.
func isValidationContext(name string) bool {
	return name == ValidationContextName || name == ValidationContextAltName
}

// getDiscoveryResponse returns the api.DiscoveryResponse for the given request.
func getDiscoveryResponse(r *discovery.DiscoveryRequest, versionInfo string, certs []*tls.Certificate, roots []*x509.Certificate) (*discovery.DiscoveryResponse, error) {
	nonce, err := randutil.Hex(64)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating nonce")
	}

	var i int
	var b []byte
	var resources []*anypb.Any
	for _, name := range r.ResourceNames {
		if isValidationContext(name) {
			b, err = getTrustedCA(name, roots)
		} else {
			b, err = getCertificateChain(name, certs[i])
			i++
		}
		if err != nil {
			return nil, err
		}
		resources = append(resources, &anypb.Any{
			TypeUrl: secretTypeURL,
			Value:   b,
		})
	}

	return &discovery.DiscoveryResponse{
		VersionInfo: versionInfo,
		Resources:   resources,
		Canary:      false,
		TypeUrl:     secretTypeURL,
		Nonce:       nonce,
		ControlPlane: &core.ControlPlane{
			Identifier: Identifier,
		},
	}, nil
}

func getTrustedCA(name string, roots []*x509.Certificate) ([]byte, error) {
	var chain bytes.Buffer
	for _, crt := range roots {
		chain.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}))
	}
	secret := auth.Secret{
		Name: name,
		Type: &auth.Secret_ValidationContext{
			ValidationContext: &auth.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: chain.Bytes()},
				},
			},
		},
	}
	v, err := proto.Marshal(&secret)
	return v, errors.Wrapf(err, "error marshaling secret")
}

func getCertificateChain(name string, cert *tls.Certificate) ([]byte, error) {
	var chain bytes.Buffer
	for _, c := range cert.Certificate {
		chain.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c,
		}))
	}

	block, err := pemutil.Serialize(cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	secret := auth.Secret{
		Name: name,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: &auth.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: chain.Bytes()},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: pem.EncodeToMemory(block)},
				},
				// Password protected keys are not supported at the moment
				// Password: &core.DataSource{
				// 	Specifier: &core.DataSource_InlineBytes{InlineBytes: nil},
				// },
			},
		},
	}

	v, err := proto.Marshal(&secret)
	return v, errors.Wrapf(err, "error marshaling secret")
}
