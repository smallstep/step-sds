package commands

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/step-sds/sds"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

func init() {
	command.Register(cli.Command{
		Name:      "init",
		Action:    cli.ActionFunc(initAction),
		Usage:     "initialize the SDS PKI",
		UsageText: `**step-sds init** --ca-url=<uri> --root=<file>`,
		Description: `**step-sds init** initializes a public key infrastructure (PKI) to be used in
the secret discovery service (SDS)`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca-url",
				Usage: "The <uri> of the targeted Step Certificate Authority.",
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The path to the PEM <file> used as the root certificate authority.",
			},
			cli.BoolFlag{
				Name:  "uds",
				Usage: "Initialize SDS with UNIX domain sockets.",
			},
		},
	})
}

func initAction(ctx *cli.Context) error {
	caURL := ctx.String("ca-url")
	if caURL == "" {
		return errs.RequiredFlag(ctx, "ca-url")
	}
	root := ctx.String("root")
	if root == "" {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return errs.RequiredFlag(ctx, "root")
		}
	}

	if ctx.Bool("uds") {
		return initUDS(caURL, root)
	}

	base := filepath.Join(step.Path(), "sds")
	if err := os.MkdirAll(base, 0700); err != nil {
		return errs.FileError(err, base)
	}

	configBase := filepath.Join(step.Path(), "config")
	if err := os.MkdirAll(configBase, 0700); err != nil {
		return errs.FileError(err, configBase)
	}

	name, err := ui.Prompt("What would you like to name your new PKI? (e.g. SDS)", ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}
	pass, err := ui.PromptPasswordGenerate("What do you want your PKI password to be? [leave empty and we'll generate one]", ui.WithRichPrompt())
	if err != nil {
		return err
	}

	address, err := ui.Prompt("What address will your new SDS server listen at? (e.g. :443)",
		ui.WithValidateFunc(ui.Address()))
	if err != nil {
		return err
	}

	serverName, err := ui.Prompt("What DNS names or IP addresses would you like to add to your SDS server? (e.g. sds.smallstep.com[,1.1.1.1,etc.])",
		ui.WithValidateFunc(ui.DNS()))
	if err != nil {
		return err
	}
	clientName, err := ui.Prompt("What would you like to name your SDS client certificate? (e.g. envoy.smallstep.com)",
		ui.WithValidateNotEmpty())
	if err != nil {
		return err
	}
	leafPass, err := ui.PromptPasswordGenerate("What do you want your certificates password to be? [leave empty and we'll generate one]", ui.WithRichPrompt())
	if err != nil {
		return err
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return err
	}

	p, err := provisionerPrompt(provisioners)
	if err != nil {
		return err
	}

	// JWK provisioner
	prov, ok := p.(*provisioner.JWK)
	if !ok {
		return errors.Errorf("unsupported provisioner type %T", p)
	}

	// Generate PKI
	ca, err := minica.New(minica.WithName(name))
	if err != nil {
		return err
	}

	// Write root certificate
	if err := createWriteCertificate(ca.Root, nil, ca.RootSigner, "root_ca.crt", "root_ca_key", pass); err != nil {
		return err
	}

	// Write intermediate
	if err := createWriteCertificate(ca.Intermediate, nil, ca.Signer, "intermediate_ca.crt", "intermediate_ca_key", pass); err != nil {
		return err
	}

	// Generate SDS server certificate
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		return err
	}
	csr, err := x509util.CreateCertificateRequest(serverName, []string{serverName}, signer)
	if err != nil {
		return err
	}
	serverCert, err := ca.SignCSR(csr, minica.WithModifyFunc(func(c *x509.Certificate) error {
		c.NotBefore = ca.Intermediate.NotBefore
		c.NotAfter = ca.Intermediate.NotAfter
		return nil
	}))
	if err != nil {
		return err
	}
	if err := createWriteCertificate(serverCert, ca.Intermediate, signer, "sds_server.crt", "sds_server_key", leafPass); err != nil {
		return err
	}

	// Generate SDS client certificate
	signer, err = keyutil.GenerateDefaultSigner()
	if err != nil {
		return err
	}
	csr, err = x509util.CreateCertificateRequest(serverName, []string{serverName}, signer)
	if err != nil {
		return err
	}
	clientCert, err := ca.SignCSR(csr, minica.WithModifyFunc(func(c *x509.Certificate) error {
		c.NotBefore = ca.Intermediate.NotBefore
		c.NotAfter = ca.Intermediate.NotAfter
		return nil
	}))
	if err != nil {
		return err
	}
	if err := createWriteCertificate(clientCert, ca.Intermediate, signer, "sds_client.crt", "sds_client_key", leafPass); err != nil {
		return err
	}

	// Generate SDS configuration
	sdsConfig := sds.Config{
		Network:               "tcp",
		Address:               address,
		Root:                  filepath.Join(base, "root_ca.crt"),
		Certificate:           filepath.Join(base, "sds_server.crt"),
		CertificateKey:        filepath.Join(base, "sds_server_key"),
		Password:              "",
		AuthorizedIdentity:    clientName,
		AuthorizedFingerprint: x509util.Fingerprint(clientCert),
		Provisioner: sds.ProvisionerConfig{
			Issuer:   prov.Name,
			KeyID:    prov.Key.KeyID,
			Password: "",
			CaURL:    caURL,
			CaRoot:   root,
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}

	configFileName := filepath.Join(configBase, "sds.json")
	b, err := json.MarshalIndent(sdsConfig, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", configFileName)
	}
	if err = fileutil.WriteFile(configFileName, b, 0666); err != nil {
		return errs.FileError(err, configFileName)
	}

	ui.Println()
	ui.PrintSelected("Root certificate", filepath.Join(base, "root_ca.crt"))
	ui.PrintSelected("Root private key", filepath.Join(base, "root_ca_key"))
	ui.PrintSelected("Intermediate certificate", filepath.Join(base, "intermediate_ca.crt"))
	ui.PrintSelected("Intermediate private key", filepath.Join(base, "intermediate_ca_key"))
	ui.PrintSelected("SDS certificate", filepath.Join(base, "sds_server.crt"))
	ui.PrintSelected("SDS private key", filepath.Join(base, "sds_server_key"))
	ui.PrintSelected("SDS client certificate", filepath.Join(base, "sds_client.crt"))
	ui.PrintSelected("SDS client private key", filepath.Join(base, "sds_client_key"))
	ui.PrintSelected("SDS configuration", configFileName)
	ui.Println()
	ui.Println("Your PKI is ready to go.")
	ui.Println("You can always generate new certificates or change passwords using step.")

	return nil
}

func initUDS(caURL, root string) error {
	configBase := filepath.Join(step.Path(), "config")
	if err := os.MkdirAll(configBase, 0700); err != nil {
		return errs.FileError(err, configBase)
	}

	dir, err := ui.Prompt("What directory do you want the UNIX domain socket 'sds.unix' to be? (e.g. /tmp)",
		ui.WithValidateFunc(func(s string) error {
			fi, err := os.Stat(s)
			if err != nil {
				return errs.FileError(err, s)
			}
			if !fi.IsDir() {
				return errors.Errorf("%s is not a directory", s)
			}
			return nil
		}))
	if err != nil {
		return err
	}

	provisioners, err := pki.GetProvisioners(caURL, root)
	if err != nil {
		return err
	}

	p, err := provisionerPrompt(provisioners)
	if err != nil {
		return err
	}

	// JWK provisioner
	prov, ok := p.(*provisioner.JWK)
	if !ok {
		return errors.Errorf("unsupported provisioner type %T", p)
	}

	// Generate SDS configuration
	address := filepath.Join(dir, "sds.unix")
	sdsConfig := sds.Config{
		Network: "unix",
		Address: address,
		Provisioner: sds.ProvisionerConfig{
			Issuer:   prov.Name,
			KeyID:    prov.Key.KeyID,
			Password: "",
			CaURL:    caURL,
			CaRoot:   root,
		},
		Logger: json.RawMessage(`{"format": "text"}`),
	}

	configFileName := filepath.Join(configBase, "sds.json")
	b, err := json.MarshalIndent(sdsConfig, "", "   ")
	if err != nil {
		return errors.Wrapf(err, "error marshaling %s", configFileName)
	}
	if err = fileutil.WriteFile(configFileName, b, 0666); err != nil {
		return errs.FileError(err, configFileName)
	}

	ui.Println()
	ui.PrintSelected("UNIX domain socket", address)
	ui.PrintSelected("SDS configuration", configFileName)
	ui.Println()
	ui.Println("Your server is ready to go.")

	return nil
}

func createWriteCertificate(cert, parent *x509.Certificate, priv crypto.PrivateKey, certName, keyName string, password []byte) error {
	base := filepath.Join(step.Path(), "sds")
	certName = filepath.Join(base, certName)
	keyName = filepath.Join(base, keyName)

	bundle := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if parent != nil {
		issuer := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: parent.Raw,
		})
		bundle = append(bundle, issuer...)
	}
	if err := fileutil.WriteFile(certName, bundle, 0600); err != nil {
		return err
	}
	_, err := pemutil.Serialize(priv, pemutil.WithPassword(password), pemutil.ToFile(keyName, 0600))
	if err != nil {
		return err
	}

	return nil
}

type provisionersSelect struct {
	Name        string
	Issuer      string
	Provisioner provisioner.Interface
}

func provisionerPrompt(provisioners provisioner.List) (provisioner.Interface, error) {
	// Filter by type
	provisioners = provisionerFilter(provisioners, func(p provisioner.Interface) bool {
		return p.GetType() == provisioner.TypeJWK
	})

	if len(provisioners) == 0 {
		return nil, errors.New("the CA does not have any JWK provisioner configured")
	}

	if len(provisioners) == 1 {
		var id, name string
		switch p := provisioners[0].(type) {
		case *provisioner.JWK:
			name = p.Name
			id = p.Key.KeyID
		default:
			return nil, errors.Errorf("unsupported provisioner type %T", p)
		}

		// Prints provisioner used
		if err := ui.PrintSelected("Key ID", id+" ("+name+")"); err != nil {
			return nil, err
		}

		return provisioners[0], nil
	}

	var items []*provisionersSelect
	for _, prov := range provisioners {
		switch p := prov.(type) {
		case *provisioner.JWK:
			items = append(items, &provisionersSelect{
				Name:        p.Key.KeyID + " (" + p.Name + ")",
				Issuer:      p.Name,
				Provisioner: p,
			})
		default:
			continue
		}
	}

	i, _, err := ui.Select("What provisioner key do you want to use?", items, ui.WithSelectTemplates(ui.NamedSelectTemplates("Key ID")))
	if err != nil {
		return nil, err
	}

	return items[i].Provisioner, nil
}

// provisionerFilter returns a slice of provisioners that pass the given filter.
func provisionerFilter(provisioners provisioner.List, f func(provisioner.Interface) bool) provisioner.List {
	var result provisioner.List
	for _, p := range provisioners {
		if f(p) {
			result = append(result, p)
		}
	}
	return result
}
