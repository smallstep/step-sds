package sds

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"golang.org/x/net/http2"
)

type renewer interface {
	ServerCertificate() *tls.Certificate
	RootCertificates() []*x509.Certificate
	RenewChannel() chan *certificate
	Stop()
}

type certificate struct {
	Name   string
	Server *tls.Certificate
	Roots  []*x509.Certificate
}

type certRenewer struct {
	cert    *tls.Certificate
	roots   []*x509.Certificate
	renewer *ca.TLSRenewer
	renewCh chan *certificate
}

func newCertRnewer(token string) (*certRenewer, error) {
	client, err := ca.Bootstrap(token)
	if err != nil {
		return nil, err
	}

	req, pk, err := ca.CreateSignRequest(token)
	if err != nil {
		return nil, err
	}

	notAfter := provisioner.TimeDuration{}
	notAfter.SetDuration(1*time.Minute + 1*time.Second)
	req.NotAfter = notAfter

	sign, err := client.Sign(req)
	if err != nil {
		return nil, err
	}

	rootCerts, err := client.Roots()
	if err != nil {
		return nil, err
	}
	roots := apiCertToX509(rootCerts.Certificates)

	cert, err := ca.TLSCertificate(sign, pk)
	if err != nil {
		return nil, err
	}

	renewer, err := client.GetCertificateRenewer(sign, pk, ca.AddRootsToCAs())
	if err != nil {
		return nil, err
	}

	renewCh := make(chan *certificate)
	renewCertificate := renewer.RenewCertificate
	renewer.RenewCertificate = func() (*tls.Certificate, error) {
		cert, err := renewCertificate()
		if err != nil {
			return nil, err
		}
		if resp, err := client.Roots(); err != nil {
			log.Println(err)
		} else {
			roots = apiCertToX509(resp.Certificates)
		}
		renewCh <- &certificate{
			Name:   cert.Leaf.Subject.CommonName,
			Server: cert,
			Roots:  roots,
		}
		return cert, nil
	}
	renewer.Run()
	return &certRenewer{
		cert:    cert,
		roots:   roots,
		renewer: renewer,
		renewCh: renewCh,
	}, nil
}

func (r *certRenewer) ServerCertificate() *tls.Certificate   { return r.cert }
func (r *certRenewer) RootCertificates() []*x509.Certificate { return r.roots }
func (r *certRenewer) RenewChannel() chan *certificate       { return r.renewCh }
func (r *certRenewer) Stop()                                 { r.renewer.Stop() }

type rootRenewer struct {
	m       sync.Mutex
	client  *ca.Client
	roots   []*x509.Certificate
	renewCh chan *certificate
	timer   *time.Timer
}

func newRootRnewer(token string) (*rootRenewer, error) {
	client, err := ca.Bootstrap(token)
	if err != nil {
		return nil, err
	}

	roots, err := client.Roots()
	if err != nil {
		return nil, err
	}

	tr, err := apiCertToTransport(roots.Certificates)
	if err != nil {
		return nil, err
	}
	client.SetTransport(tr)

	r := &rootRenewer{
		client:  client,
		roots:   apiCertToX509(roots.Certificates),
		renewCh: make(chan *certificate),
	}
	r.timer = time.AfterFunc(ValidationContextRenewPeriod, r.renewRoots)
	return r, nil
}

func (r *rootRenewer) ServerCertificate() *tls.Certificate   { return nil }
func (r *rootRenewer) RootCertificates() []*x509.Certificate { return r.roots }
func (r *rootRenewer) RenewChannel() chan *certificate       { return r.renewCh }
func (r *rootRenewer) Stop()                                 { r.timer.Stop() }

func (r *rootRenewer) renewRoots() {
	resp, err := r.client.Roots()
	if err != nil {
		time.AfterFunc(ValidationContextRenewPeriod/20, r.renewRoots)
		return
	}
	roots := apiCertToX509(resp.Certificates)
	if !reflect.DeepEqual(roots, r.roots) {
		r.roots = roots
		time.AfterFunc(ValidationContextRenewPeriod, r.renewRoots)
		r.renewCh <- &certificate{
			Roots: roots,
		}
	}
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
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			RootCAs:                  pool,
		},
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return nil, errors.Wrap(err, "error configuring transport")
	}
	return tr, nil
}
