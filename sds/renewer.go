package sds

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
	"golang.org/x/net/http2"
)

type secrets struct {
	Roots        []*x509.Certificate
	Certificates []*tls.Certificate
}

type secretRenewer struct {
	m            sync.RWMutex
	client       *ca.Client
	roots        []*x509.Certificate
	certificates []*tls.Certificate
	transports   []*http.Transport
	timer        *time.Timer
	renewPeriod  time.Duration
	renewCh      chan secrets
}

func newSecretRenewer(tokens []string) (*secretRenewer, error) {
	if len(tokens) == 0 {
		return nil, errors.New("missing tokens")
	}

	client, err := ca.Bootstrap(tokens[0])
	if err != nil {
		return nil, err
	}

	roots, err := client.Roots()
	if err != nil {
		return nil, err
	}

	s := &secretRenewer{
		roots:   apiCertToX509(roots.Certificates),
		client:  client,
		renewCh: make(chan secrets),
	}

	for _, tok := range tokens {
		subject, err := getTokenSubject(tok)
		if err != nil {
			return nil, err
		}

		if !isValidationContext(subject) {
			cert, tr, err := s.sign(tok)
			if err != nil {
				return nil, err
			}
			s.certificates = append(s.certificates, cert)
			s.transports = append(s.transports, tr)
		}
	}
	if len(s.certificates) > 0 {
		validity := s.certificates[0].Leaf.NotAfter.Sub(s.certificates[0].Leaf.NotBefore)
		s.renewPeriod = validity / 3
	} else {
		s.renewPeriod = ValidationContextRenewPeriod
	}

	// Initialize renewer
	s.timer = time.AfterFunc(s.renewPeriod, s.doRenew)
	return s, nil
}

// Stop stops the renewer
func (s *secretRenewer) Stop() {
	s.timer.Stop()
	close(s.renewCh)
}

// Secrets returns the current secrets.
func (s *secretRenewer) Secrets() secrets {
	s.m.RLock()
	defer s.m.RUnlock()
	return secrets{
		Roots:        s.roots,
		Certificates: s.certificates,
	}
}

// RenewChannel returns the channel that will receive all the certificates.
func (s *secretRenewer) RenewChannel() chan secrets {
	return s.renewCh
}

func (s *secretRenewer) doRenew() {
	if err := s.renew(); err != nil {
		s.timer.Reset(s.renewPeriod / 20)
		return
	}
	s.timer.Reset(s.renewPeriod)
	select {
	case s.renewCh <- s.Secrets():
	default:
	}
}

// Sign signs creates a new CSR ands sends it to the CA to sign it, it returns
// the signed certificate, and a transport configured with the certificate.
func (s *secretRenewer) sign(token string) (*tls.Certificate, *http.Transport, error) {
	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return nil, nil, err
	}

	sign, err := s.client.Sign(req)
	if err != nil {
		return nil, nil, err
	}

	return s.createCertAndTransport(sign, pk)
}

func (s *secretRenewer) renew() error {
	s.m.Lock()
	defer s.m.Unlock()

	// Update new roots
	roots, err := s.client.Roots()
	if err != nil {
		return err
	}
	s.roots = apiCertToX509(roots.Certificates)

	// Update client transport with new roots
	tr, err := apiCertToTransport(roots.Certificates)
	if err != nil {
		return err
	}
	s.client.SetTransport(tr)

	// Update certificates
	for i, cert := range s.certificates {
		sign, err := s.client.Renew(s.transports[i])
		if err != nil {
			return err
		}

		crt, tr, err := s.createCertAndTransport(sign, cert.PrivateKey)
		if err != nil {
			return err
		}
		s.certificates[i] = crt
		s.transports[i] = tr
	}

	return nil
}

func (s *secretRenewer) createCertAndTransport(sign *api.SignResponse, pk crypto.PrivateKey) (*tls.Certificate, *http.Transport, error) {
	cert, err := ca.TLSCertificate(sign, pk)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := getDefaultTLSConfig(sign)
	tlsConfig.Certificates = []tls.Certificate{*cert}
	if len(s.roots) > 0 {
		pool := x509.NewCertPool()
		for _, cert := range s.roots {
			pool.AddCert(cert)
		}
		tlsConfig.RootCAs = pool
	}

	tr, err := getDefaultTransport(tlsConfig)
	if err != nil {
		return nil, nil, err
	}

	return cert, tr, nil
}

func getTokenSubject(token string) (string, error) {
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}
	var claims jose.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", errors.Wrap(err, "error parsing token")
	}
	return claims.Subject, nil
}

func apiCertToX509(certs []api.Certificate) []*x509.Certificate {
	ret := make([]*x509.Certificate, len(certs))
	for i := range certs {
		ret[i] = certs[i].Certificate
	}
	return ret
}

func apiCertToTransport(certs []api.Certificate) (http.RoundTripper, error) {
	pool := x509.NewCertPool()
	for _, crt := range certs {
		pool.AddCert(crt.Certificate)
	}

	return getDefaultTransport(&tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  pool,
	})
}

func getDefaultTLSConfig(sign *api.SignResponse) *tls.Config {
	if sign.TLSOptions != nil {
		return sign.TLSOptions.TLSConfig()
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// getDefaultTransport returns an http.Transport with the same parameters than
// http.DefaultTransport, but adds the given tls.Config and configures the
// transport for HTTP/2.
func getDefaultTransport(tlsConfig *tls.Config) (*http.Transport, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.Wrap(err, "error configuring transport")
	}
	return tr, nil
}
