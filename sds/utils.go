package sds

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	types "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/randutil"
)

const secretTypeURL = "type.googleapis.com/envoy.api.v2.auth.Secret"

// isValidationContext returns if the given name is one of the predefined
// validation context names.
func isValidationContext(name string) bool {
	return name == ValidationContextName || name == ValidationContextAltName
}

// getSubject returns a resource name if it's not a validation context name
func getSubject(r *api.DiscoveryRequest) (string, bool) {
	for _, name := range r.ResourceNames {
		if !isValidationContext(name) {
			return name, true
		}
	}
	return "", false
}

// getDiscoveryResponse returns the api.DiscoveryResponse for the given request.
func getDiscoveryResponse(r *api.DiscoveryRequest, versionInfo string, cert *tls.Certificate, roots []*x509.Certificate) (*api.DiscoveryResponse, error) {
	nonce, err := randutil.Hex(64)
	if err != nil {
		return nil, errors.Wrapf(err, "error generating nonce")
	}

	var b []byte
	var resources []types.Any
	for _, name := range r.ResourceNames {
		if isValidationContext(name) {
			b, err = getTrustedCA(name, roots)
		} else {
			b, err = getCertificateChain(name, cert)
		}
		if err != nil {
			return nil, err
		}
		resources = append(resources, types.Any{
			TypeUrl: secretTypeURL,
			Value:   b,
		})
	}

	return &api.DiscoveryResponse{
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
	v, err := secret.Marshal()
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

	v, err := secret.Marshal()
	return v, errors.Wrapf(err, "error marshaling secret")
}
