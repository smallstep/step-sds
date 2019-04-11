package sds

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

// Config is the configuration used to initialize the SDS Service.
type Config struct {
	Network               string            `json:"network"`
	Address               string            `json:"address"`
	Root                  string            `json:"root,omitempty"`
	Certificate           string            `json:"crt,omitempty"`
	CertificateKey        string            `json:"key,omitempty"`
	Password              string            `json:"password,omitempty"`
	AuthorizedIdentity    string            `json:"authorizedIdentity"`
	AuthorizedFingerprint string            `json:"authorizedFingerprint"`
	Provisioner           ProvisionerConfig `json:"provisioner"`
	Logger                json.RawMessage
}

// IsTCP returns if the network is tcp, tcp4, or tcp6.
func (c Config) IsTCP() bool {
	return c.Network == "tcp" || c.Network == "tcp4" || c.Network == "tcp6"
}

// Validate validates the configuration in Config.
func (c Config) Validate() error {
	switch {
	case c.Network == "":
		return errors.New("network cannot be empty")
	case c.Address == "":
		return errors.New("address cannot be empty")
	}

	var tcp bool
	if c.IsTCP() {
		tcp = true
	} else if c.Network != "unix" && c.Network != "unixpacket" {
		return errors.Errorf(`invalid value "%s" for "network", options are tcp, tcp4, tcp6, unix or unixpacket`, c.Network)
	}

	if tcp {
		// root can be empty if the certs are trusted by the system
		switch {
		case c.Certificate == "":
			return errors.Errorf("crt cannot be empty if network is %s", c.Network)
		case c.CertificateKey == "":
			return errors.Errorf("key cannot be empty if network is %s", c.Network)
		}
	}

	return c.Provisioner.Validate()
}

// ProvisionerConfig is the configuration used to initialize the provisioner.
type ProvisionerConfig struct {
	Issuer   string `json:"issuer"`
	KeyID    string `json:"kid"`
	Password string `json:"password,omitempty"`
	CaURL    string `json:"ca-url"`
	CaRoot   string `json:"root"`
}

// Validate validates the configuration in ProvisionerConfig.
func (c ProvisionerConfig) Validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("provisioner.issuer cannot be empty")
	case c.KeyID == "":
		return errors.New("provisioner.kid cannot be empty")
	case c.CaURL == "":
		return errors.New("provisioner.ca-url cannot be empty")
	case c.CaRoot == "":
		return errors.New("provisioner.root cannot be empty")
	}
	return nil
}

// LoadConfiguration parses the given filename in JSON format and returns the
// configuration struct.
func LoadConfiguration(filename string) (Config, error) {
	var c Config

	f, err := os.Open(filename)
	if err != nil {
		return c, errors.Wrapf(err, "error opening %s", filename)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return c, errors.Wrapf(err, "error parsing %s", filename)
	}

	return c, c.Validate()
}
