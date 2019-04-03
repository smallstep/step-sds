package sds

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"time"

	"github.com/smallstep/certificates/api"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
)

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
		log.Printf("certificated renewed: notBefore: %s, notAfter:%s\n", cert.Leaf.NotBefore.String(), cert.Leaf.NotAfter.String())
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

func apiCertToX509(certs []api.Certificate) []*x509.Certificate {
	ret := make([]*x509.Certificate, len(certs))
	for i := range certs {
		ret[i] = certs[i].Certificate
	}
	return ret
}
