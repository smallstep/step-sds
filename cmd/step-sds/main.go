package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"time"
	"unicode"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/step-sds/logging"
	"github.com/smallstep/step-sds/sds"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// commit and buildTime are filled in during build by the Makefile
var (
	BuildTime = "N/A"
	Version   = "N/A"
)

func init() {
	if Version == "N/A" {
		sds.Identifier = "Smallstep SDS/0000000-dev"
	} else {
		sds.Identifier = fmt.Sprintf("Smallstep SDS/%s", Version)
	}
}

// getVersion returns the current version of the binary.
func getVersion() string {
	out := Version
	if out == "N/A" {
		out = "0000000-dev"
	}
	return fmt.Sprintf("Smallstep SDS/%s (%s/%s)",
		out, runtime.GOOS, runtime.GOARCH)
}

// getReleaseDate returns the time of when the binary was built.
func getReleaseDate() string {
	out := BuildTime
	if out == "N/A" {
		out = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}

	return out
}

// Print version and release date.
func printFullVersion() {
	fmt.Printf("%s\n", getVersion())
	fmt.Printf("Release Date: %s\n", getReleaseDate())
}

func fail(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func failf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func main() {
	var network, address string
	var certFile, keyFile, rootFile string
	var authorizedIdentity, authorizedFingerprint string
	var kid, issuer, passwordFile string
	var caURL, caRoot string
	var version bool
	flag.StringVar(&network, "network", "tcp", `The network to listen to ("tcp", "tcp4", "tcp6", "unix" or "unixpacket")`)
	flag.StringVar(&address, "address", "127.0.0.1:443", "The local network address (a tcp or a path)")
	flag.StringVar(&certFile, "cert", "", "The TLS certificate path")
	flag.StringVar(&keyFile, "key", "", "The TLS certificate key path")
	flag.StringVar(&rootFile, "root", "", "The Root CA certificate path")
	flag.StringVar(&authorizedIdentity, "authorized-identity", "", "The identity of an authorized SDS client (e.g. envoy.smallstep.com)")
	flag.StringVar(&authorizedFingerprint, "authorized-fingerprint", "", "The fingerprint of the SDS client certificate")
	flag.StringVar(&kid, "kid", "", "The certificate provisioner kid used to get a certificate")
	flag.StringVar(&issuer, "issuer", "", "The certificate provisioner issuer used to get a certificate")
	flag.StringVar(&passwordFile, "password-file", "", "The path to a file with the certificate provisioner password")
	flag.StringVar(&caURL, "ca-url", "", "The URI of the targeted Step Certificate Authority")
	flag.StringVar(&caRoot, "ca-root", "", "The path to the PEM file used as the root certificate authority")
	flag.BoolVar(&version, "version", false, "Print the version")
	flag.Parse()

	if version {
		printFullVersion()
		os.Exit(0)
	}

	// Flag validation
	switch {
	case network == "":
		fail("flag '--network' is required")
	case address == "":
		fail("flag '--address' is required")
	case kid != "" && issuer == "":
		fail("flag '--kid' requires the '--issuer' flag")
	case kid != "" && caURL == "" && caRoot == "":
		fail("flag '--kid' requires the '--ca-url' and '--ca-root' flags")
	case kid != "" && caURL == "":
		fail("flag '--kid' requires the '--ca-url' flag")
	case kid != "" && caRoot == "":
		fail("flag '--provisioner' requires the '--ca-root' flag")
	}

	var err error
	var password []byte
	if kid != "" {
		if passwordFile == "" {
			password, err = ui.PromptPassword("Please enter the password to encrypt the provisioner key")
			if err != nil {
				fail(err)
			}
		} else {
			b, err := ioutil.ReadFile(passwordFile)
			if err != nil {
				fail(err)
			}
			password = bytes.TrimRightFunc(b, unicode.IsSpace)
		}
	}

	var tcp bool
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		tcp = true
	} else if network != "unix" && network != "unixpacket" {
		failf("invalid value '%s' for flag '--network', options are tcp, tcp4, tcp6, unix or unixpacket", network)
	}

	switch {
	case tcp && certFile == "":
		failf("flag '--cert' is required with a '%s' address", network)
	case tcp && keyFile == "":
		failf("flag '--key' is required with a '%s' address", network)
	}

	config := sds.Config{
		AuthorizedIdentity:    authorizedIdentity,
		AuthorizedFingerprint: authorizedFingerprint,
		Provisioner: sds.ProvisionerConfig{
			Issuer:   issuer,
			KeyID:    kid,
			Password: string(password),
			CaURL:    caURL,
			CaRoot:   caRoot,
		},
		Logger: json.RawMessage("{}"),
	}

	logger, err := logging.New("step-sds", config.Logger)
	if err != nil {
		failf("error initializing logger: %v", err)
	}

	// Start gRPC server
	opts := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(logging.UnaryServerInterceptor(logger)),
		grpc_middleware.WithStreamServerChain(logging.StreamServerInterceptor(logger)),
	}

	if tcp {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fail(err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}
		if rootFile != "" {
			b, err := ioutil.ReadFile(rootFile)
			if err != nil {
				fail(err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				failf("failed to successfully load root certificates from %s", rootFile)
			}
			tlsConfig.ClientCAs = pool

		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	lis, err := net.Listen(network, address)
	if err != nil {
		fail(err)
	}

	s, err := sds.New(config)
	if err != nil {
		fail(err)
	}

	srv := grpc.NewServer(opts...)
	s.Register(srv)
	go ca.StopHandler(&stopper{srv: srv, sds: s})

	log.Printf("Serving at %s://%s ...", network, lis.Addr())
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err)
	}
}

// stopper is a wrapper to be able to use the ca.StopHandler.
type stopper struct {
	srv *grpc.Server
	sds *sds.Service
}

func (s *stopper) Stop() error {
	if err := s.sds.Stop(); err != nil {
		return err
	}
	s.srv.GracefulStop()
	return nil
}
