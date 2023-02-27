package sds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/smallstep/certificates/ca"
)

const testRootCA = `-----BEGIN CERTIFICATE-----
MIIBfTCCASKgAwIBAgIRAL1Zxx31uy4dIOSCt2kuKC0wCgYIKoZIzj0EAwIwHDEa
MBgGA1UEAxMRU21hbGxzdGVwIFJvb3QgQ0EwHhcNMTkwNDA0MDEyMjUxWhcNMjkw
NDAxMDEyMjUxWjAcMRowGAYDVQQDExFTbWFsbHN0ZXAgUm9vdCBDQTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABG7Ko6ayB4RjmQh2WGOjv82WQcxOBM2u5D2myoiO
+PSvFKT9FStbJuecpkklodvUNCbPQEkAYBmY0FZrxBnj6mejRTBDMA4GA1UdDwEB
/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBQRKE4dS5tk6y/o
uUmZYVJzSatOtDAKBggqhkjOPQQDAgNJADBGAiEA735TJeWTep1bogjBBwJFkAl4
Snm6cD8U31nTGU1LacICIQDJ2C96GQZPz9BnSp6kHdj8OiRAnqkVaCXqio6vH+Jf
NA==
-----END CERTIFICATE-----`

const testIntermediateCert = `-----BEGIN CERTIFICATE-----
MIIBpDCCAUqgAwIBAgIQMWAbaDjPtFO0kTTL3SD1WzAKBggqhkjOPQQDAjAcMRow
GAYDVQQDExFTbWFsbHN0ZXAgUm9vdCBDQTAeFw0xOTA0MDQwMTIyNTFaFw0yOTA0
MDEwMTIyNTFaMCQxIjAgBgNVBAMTGVNtYWxsc3RlcCBJbnRlcm1lZGlhdGUgQ0Ew
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdoeXL9SXbbHII9tCc6nW6HHz18+zK
aTF5cxdyQ12Z6pnyDXntRdiZzfCVX76B+xmoablSrFwQ7Q6fdFEECtLyo2YwZDAO
BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUQzNY
WbowdwotixBbGLCXiifU9w0wHwYDVR0jBBgwFoAUEShOHUubZOsv6LlJmWFSc0mr
TrQwCgYIKoZIzj0EAwIDSAAwRQIgSp+I9hTBxZalO+HtdHp1Uqj7WScQuz7ZbQK8
I8AXuxYCIQC3QLLDPpECUZ3jaIVS1HUmahbHtgMnM2lUOaBd5lxi6A==
-----END CERTIFICATE-----`

const testIntermediateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC98xDs7yDxta9nf+Rys/9hV0xwg6HFlMkdhYs5SXxVkoAoGCCqGSM49
AwEHoUQDQgAEnaHly/Ul22xyCPbQnOp1uhx89fPsymkxeXMXckNdmeqZ8g157UXY
mc3wlV++gfsZqGm5UqxcEO0On3RRBArS8g==
-----END EC PRIVATE KEY-----`

const testCert = `-----BEGIN CERTIFICATE-----
MIICJzCCAcygAwIBAgIQCmQworM3l13fYC96U7Z+zTAKBggqhkjOPQQDAjAkMSIw
IAYDVQQDExlTbWFsbHN0ZXAgSW50ZXJtZWRpYXRlIENBMB4XDTE5MDUxMzIyMDIw
MVoXDTE5MDUxMzIyMDMwMVowHDEaMBgGA1UEAxMRZm9vLnNtYWxsc3RlcC5jb20w
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATtCCL7U+jtMhbD3ZklQXvdq11qz3C4
wis/MLlIJ7K7EX3H32sK9s8o4JL/AhuR+NGAAZg/+spTO99DVW46eVcco4HnMIHk
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
HQYDVR0OBBYEFLfH6P8CKtU/2oj3aed8blx7Q+K+MB8GA1UdIwQYMBaAFEMzWFm6
MHcKLYsQWxiwl4on1PcNMBwGA1UdEQQVMBOCEWZvby5zbWFsbHN0ZXAuY29tMFUG
DCsGAQQBgqRkxihAAQRFMEMCAQEEEXNkc0BzbWFsbHN0ZXAuY29tBCtvQTF4Mm5W
M3lDbGFmMmtRZFBPSl9MRXpUR3c1b3c0cjJBNVNXbDNNZk1nMAoGCCqGSM49BAMC
A0kAMEYCIQDTh5dTtpuGI5fMKOhg/j3jaMhRy7s18wyt1UzOtNw4/AIhALt596cL
VkRXF2/FSjdSgvS0E/37Aaz/yUeX3OCAmfMe
-----END CERTIFICATE-----`

const testCertKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM7Zfr3bqP69RJLHGMKMJldWeCIsn0BLZG12WgfeziX6oAoGCCqGSM49
AwEHoUQDQgAE7Qgi+1Po7TIWw92ZJUF73atdas9wuMIrPzC5SCeyuxF9x99rCvbP
KOCS/wIbkfjRgAGYP/rKUzvfQ1VuOnlXHA==
-----END EC PRIVATE KEY-----`

func Test_isValidationContext(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"trusted_ca", args{"trusted_ca"}, true},
		{"validation_context", args{"validation_context"}, true},
		{"empty", args{""}, false},
		{"other", args{"other"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidationContext(tt.args.name); got != tt.want {
				t.Errorf("isValidationContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDiscoveryResponse(t *testing.T) {
	roots := rootCAs(t)
	certs := tlsCerts(t)

	cert, err := getCertificateChain("foo.smallstep.com", certs[0])
	if err != nil {
		t.Fatal(err)
	}
	trustedCA, err := getTrustedCA("trusted_ca", roots)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		resourceNames []string
		value         []byte
		err           bool
	}{
		0: {
			resourceNames: []string{"foo.smallstep.com"},
			value:         cert,
		},
		1: {
			resourceNames: []string{"trusted_ca"},
			value:         trustedCA,
		},
	}

	for caseIndex := range cases {
		kase := cases[caseIndex]

		t.Run(strconv.Itoa(caseIndex), func(t *testing.T) {
			req := &discovery.DiscoveryRequest{
				VersionInfo: "versionInfo",
				Node: &core.Node{
					Id:      "node-id",
					Cluster: "node-cluster",
				},
				ResourceNames: kase.resourceNames,
				TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
				ResponseNonce: "response-nonce",
			}

			got, err := getDiscoveryResponse(req, "versionInfo", certs, roots)
			if kase.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if got != nil {
				got.Nonce = "nonce"
			}

			exp := &discovery.DiscoveryResponse{
				VersionInfo: "versionInfo",
				Resources: []*anypb.Any{
					{
						TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
						Value:   kase.value,
					},
				},
				Canary:  false,
				TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
				Nonce:   "nonce",
				ControlPlane: &core.ControlPlane{
					Identifier: Identifier,
				},
			}

			assert.Equal(t, exp, got)
		})
	}
}

func rootCAs(t *testing.T) []*x509.Certificate {
	t.Helper()

	b, _ := pem.Decode([]byte(testRootCA))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert}
}

func tlsCerts(t *testing.T) []*tls.Certificate {
	t.Helper()

	var b *pem.Block
	cert := new(tls.Certificate)
	b, _ = pem.Decode([]byte(testCert))

	cert.Certificate = append(cert.Certificate, b.Bytes)
	b, _ = pem.Decode([]byte(testIntermediateCert))

	cert.Certificate = append(cert.Certificate, b.Bytes)
	b, _ = pem.Decode([]byte(testCertKey))

	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert.PrivateKey = key

	return []*tls.Certificate{cert}
}

func mustSign(csr *x509.CertificateRequest, validity time.Duration) *tls.Certificate {
	b, _ := pem.Decode([]byte(testIntermediateCert))
	issuer, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	b, _ = pem.Decode([]byte(testIntermediateKey))
	issuerKey, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: sn,
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		Issuer:                issuer.Subject,
		Subject:               csr.Subject,
		Extensions:            csr.Extensions,
		ExtraExtensions:       csr.ExtraExtensions,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, issuer, csr.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{
			cert, issuer.Raw,
		},
	}
}

func caServer(signValidity time.Duration) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/roots", "/1.0/roots":
			sendJSON(w, map[string]interface{}{
				"crts": []string{testRootCA},
			})
		case "/root/154fa6239ba9839f50b6a17f71addb77e4c478db116a2fbb08256faa786245f5":
			sendJSON(w, map[string]interface{}{
				"ca": testRootCA,
			})
		case "/sign", "/1.0/sign":
			body := struct {
				CsrPEM string `json:"csr"`
			}{}
			readJSON(w, r, &body)
			b, _ := pem.Decode([]byte(body.CsrPEM))
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			crt := mustSign(csr, signValidity)
			sendJSON(w, map[string]interface{}{
				"crt": string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: crt.Certificate[0],
				})),
				"ca": testIntermediateCert,
			})
		case "/renew", "/1.0/renew":
			cert := r.TLS.PeerCertificates[0]
			crt := mustSign(&x509.CertificateRequest{
				Subject:        cert.Subject,
				DNSNames:       cert.DNSNames,
				EmailAddresses: cert.EmailAddresses,
				IPAddresses:    cert.IPAddresses,
				URIs:           cert.URIs,
				PublicKey:      cert.PublicKey,
			}, signValidity)
			sendJSON(w, map[string]interface{}{
				"crt": string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: crt.Certificate[0],
				})),
				"ca": testIntermediateCert,
			})
		case "/provisioners":
			sendJSON(w, map[string]interface{}{
				"provisioners": []map[string]interface{}{
					{
						"type": "jwk",
						"name": "sds@smallstep.com",
						"key": map[string]interface{}{
							"use": "sig",
							"kty": "EC",
							"kid": "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
							"crv": "P-256",
							"alg": "ES256",
							"x":   "RSYrm1bAJJi4GvEAZEh54mxWUhAwPzikqODPqWwoan0",
							"y":   "4m1tk74nGi0TmdO6xbqwmVtmz1TG6V6kMCGcj6p5d9o",
						},
					},
				},
				"nextCursor": "",
			})
		case "/provisioners/oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg/encrypted-key":
			sendJSON(w, map[string]interface{}{
				"key": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiMnYtTVAzTWJIUXJqREpkOVJzVmpxUSJ9.A2T_-8X5YUiVsjH-RAdnok8Lx53LEdNWM0Mj-DD_ZLMrhGmGhWP_oA.vOEhddCzj_hfclUX.gT6ofpR9EiukrOQsmlpd0pr3RKcmQ-G9NLGn2Pv5vO_Ncyk0WiHko5z-SYDBIRi73AxHrny6up4nZTcmesKzw2cuZKenJ-vZelKKtHm-7788crpNTQcUhBP2tLDxonmf-0bMt0vza6vl3CYlhXh7qslN6YfW1OFwwja9UvDoiotut6jcohYaNVvxwb7j-GpDJkXNQ-ybAPrMh8OLNOIGjugoZxYGWD-4sY-ZO-3qsl43JxjbC-oFE_TcxK4P0tfg88dT6D14EOL767EikJuvu34N6QO_JcvamdwyuVzlCYyvuIkrkQPr8bKdrA8QeLH5Vw4Imo1Y9Tsv9VNZHAI.rFAtSMuB84tv_LT8RDMVAg",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// Create Local Certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "Test CA"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, key)
	if err != nil {
		panic(err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}
	cert := mustSign(csr, time.Hour)
	cert.PrivateKey = key

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(testRootCA))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	return srv
}

func sendJSON(w http.ResponseWriter, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func caProvisioner(srv *httptest.Server) *ca.Provisioner {
	p, err := ca.NewProvisioner("sds@smallstep.com", "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg", srv.URL, []byte("password"), ca.WithRootFile("testdata/root_ca.crt"))
	if err != nil {
		panic(err)
	}
	return p
}
