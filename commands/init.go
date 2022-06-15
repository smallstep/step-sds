package commands

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/step-sds/sds"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/ui"
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

	base := filepath.Join(config.StepPath(), "sds")
	if err := os.MkdirAll(base, 0700); err != nil {
		return errs.FileError(err, base)
	}

	configBase := filepath.Join(config.StepPath(), "config")
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

	// Generate root
	rootProfile, err := x509util.NewRootProfile(name)
	if err != nil {
		return err
	}
	rootCrt, err := createWriteCertificate(rootProfile, "root_ca.crt", "root_ca_key", pass)
	if err != nil {
		return err
	}

	// Generate intermediate
	interProfile, err := x509util.NewIntermediateProfile(name, rootCrt, rootProfile.SubjectPrivateKey())
	if err != nil {
		return err
	}
	interCrt, err := createWriteCertificate(interProfile, "intermediate_ca.crt", "intermediate_ca_key", pass)
	if err != nil {
		return err
	}

	// Generate SDS server certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(x509util.DefaultIntermediateCertValidity)
	serverProfile, err := x509util.NewLeafProfile(serverName, interCrt, interProfile.SubjectPrivateKey(),
		x509util.WithHosts(serverName), x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0))
	if err != nil {
		return err
	}
	_, err = createWriteCertificate(serverProfile, "sds_server.crt", "sds_server_key", leafPass)
	if err != nil {
		return err
	}

	// Generate SDS client certificate
	clientProfile, err := x509util.NewLeafProfile(clientName, interCrt, interProfile.SubjectPrivateKey(),
		x509util.WithNotBeforeAfterDuration(notBefore, notAfter, 0))
	if err != nil {
		return err
	}
	clientCrt, err := createWriteCertificate(clientProfile, "sds_client.crt", "sds_client_key", leafPass)
	if err != nil {
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
		AuthorizedFingerprint: x509util.Fingerprint(clientCrt),
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
	if err = utils.WriteFile(configFileName, b, 0666); err != nil {
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
	configBase := filepath.Join(config.StepPath(), "config")
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
	if err = utils.WriteFile(configFileName, b, 0666); err != nil {
		return errs.FileError(err, configFileName)
	}

	ui.Println()
	ui.PrintSelected("UNIX domain socket", address)
	ui.PrintSelected("SDS configuration", configFileName)
	ui.Println()
	ui.Println("Your server is ready to go.")

	return nil
}

func createWriteCertificate(profile x509util.Profile, certName, keyName string, password []byte) (*x509.Certificate, error) {
	base := filepath.Join(config.StepPath(), "sds")
	certName = filepath.Join(base, certName)
	keyName = filepath.Join(base, keyName)

	b, err := profile.CreateCertificate()
	if err != nil {
		return nil, err
	}

	bundle := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	if _, ok := profile.(*x509util.Leaf); ok {
		issuer := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: profile.Issuer().Raw,
		})
		bundle = append(bundle, issuer...)
	}
	if err := utils.WriteFile(certName, bundle, 0600); err != nil {
		return nil, err
	}
	_, err = pemutil.Serialize(profile.SubjectPrivateKey(), pemutil.WithPassword(password), pemutil.ToFile(keyName, 0600))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	crt, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}

	return crt, nil
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
