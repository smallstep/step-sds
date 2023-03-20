package commands

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/step-sds/logging"
	"github.com/smallstep/step-sds/sds"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func init() {
	command.Register(cli.Command{
		Name:      "run",
		Action:    cli.ActionFunc(runAction),
		Usage:     "run the SDS server",
		UsageText: "**step-sds run** <config> [--password-file=<file>] [--provisioner-password-file=<file>]",
		Description: `**step-sds run** starts a secret discovery service (SDS) using the given configuration.

## POSITIONAL ARGUMENTS

<config>
: File that configures the operation of the Step SDS; this file is generated
when you initialize the Step SDS using **step-sds init**

## EXIT CODES

This command will run indefinitely on success and return \>0 if any error occurs.

## EXAMPLES

These examples assume that you have already initialized your PKI by running
'step-sds init'. If you have not completed this step please see the 'Getting Started'
section of the README.

Run the Step SDS and prompt for the certificate and provisioner passwords:
'''
$ step-sds $STEPPATH/config/sds.json
'''

Run the Step SDS and read the passwords from files - this is useful for
automating deployment:
'''
$ step-sds $STEPPATH/config/sds.json \
	--password-file ./certificate-key-password.txt \
	--provisioner-password-file ./provisioner-password.txt
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "password-file",
				Usage: `Path to the <file> containing the password to decrypto the key.`,
			},
			cli.StringFlag{
				Name:  "provisioner-password-file",
				Usage: `Path to the <file> containing the provisioning password.`,
			},
		},
	})
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

func runAction(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return cli.ShowAppHelp(ctx)
	}

	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	c, err := sds.LoadConfiguration(ctx.Args().First())
	if err != nil {
		return err
	}

	passwordFile := ctx.String("password-file")
	provPasswordFile := ctx.String("provisioner-password-file")
	if provPasswordFile == "" && c.Provisioner.Password == "" {
		password, err := ui.PromptPassword("Please enter the password to decrypt the provisioner key")
		if err != nil {
			return err
		}
		c.Provisioner.Password = string(password)
	}
	if provPasswordFile != "" {
		b, err := readPasswordFromFile(provPasswordFile)
		if err != nil {
			return err
		}
		c.Provisioner.Password = string(b)
	}

	logger, err := logging.New("step-sds", c.Logger)
	if err != nil {
		return errors.Wrap(err, "error initializing logger")
	}

	// Start gRPC server
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(logging.UnaryServerInterceptor(logger)),
		grpc.ChainStreamInterceptor(logging.StreamServerInterceptor(logger)),
	}

	if c.IsTCP() {
		// Parse certificate
		crtPEM, err := os.ReadFile(c.Certificate)
		if err != nil {
			return err
		}
		// Parse key, it can be encrypted
		pemOpts := []pemutil.Options{
			pemutil.WithFilename(c.CertificateKey),
		}
		if passwordFile != "" {
			pemOpts = append(pemOpts, pemutil.WithPasswordFile(passwordFile))
		} else if c.Password != "" {
			pemOpts = append(pemOpts, pemutil.WithPassword([]byte(c.Password)))
		}
		keyBytes, err := os.ReadFile(c.CertificateKey)
		if err != nil {
			return errs.FileError(err, c.CertificateKey)
		}
		key, err := pemutil.Parse(keyBytes, pemOpts...)
		if err != nil {
			return err
		}
		keyPEM, err := pemutil.Serialize(key)
		if err != nil {
			return err
		}
		// Load TLS certificate and create TLS config
		cert, err := tls.X509KeyPair(crtPEM, pem.EncodeToMemory(keyPEM))
		if err != nil {
			return errors.Wrap(err, "error loading certificate")
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}
		if c.Root != "" {
			b, err := os.ReadFile(c.Root)
			if err != nil {
				return errs.FileError(err, c.Root)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return errors.Errorf("failed to successfully load root certificates from %s", c.Root)
			}
			tlsConfig.ClientCAs = pool
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	lis, err := net.Listen(c.Network, c.Address)
	if err != nil {
		return errors.Wrapf(err, "error listening using network '%s' and address '%s'", c.Network, c.Address)
	}

	s, err := sds.New(c)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(opts...)
	s.Register(srv)
	go ca.StopHandler(&stopper{srv: srv, sds: s})

	fields := logging.Fields{
		"grpc.start_time": time.Now().Format(logger.GetTimeFormat()),
	}
	logger.WithFields(fields).Infof("Serving at %s://%s ...", c.Network, lis.Addr())
	if err := srv.Serve(lis); err != nil {
		return errors.Wrap(err, "error serving gRPC")
	}

	return nil
}

// readPasswordFromFile reads and returns the password from the given filename.
// The contents of the file will be trimmed at the right.
func readPasswordFromFile(filename string) ([]byte, error) {
	password, err := os.ReadFile(filename)
	if err != nil {
		return nil, errs.FileError(err, filename)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)
	return password, nil
}
