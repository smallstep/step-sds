package sds

import (
	"reflect"
	"testing"
)

func TestConfig_IsTCP(t *testing.T) {
	type fields struct {
		Network string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"tcp", fields{"tcp"}, true},
		{"tcp4", fields{"tcp4"}, true},
		{"tcp6", fields{"tcp6"}, true},
		{"unix", fields{"unix"}, false},
		{"unixpacket", fields{"unixpacket"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				Network: tt.fields.Network,
			}
			if got := c.IsTCP(); got != tt.want {
				t.Errorf("Config.IsTCP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	p := ProvisionerConfig{
		Issuer:   "issuer",
		KeyID:    "key-id",
		Password: "password",
		CaURL:    "https://ca",
		CaRoot:   "root.crt",
	}
	type fields struct {
		Network               string
		Address               string
		Root                  string
		Certificate           string
		CertificateKey        string
		Password              string
		AuthorizedIdentity    string
		AuthorizedFingerprint string
		Provisioner           ProvisionerConfig
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok tcp", fields{"tcp", ":443", "root.crt", "cert.crt", "cert.key", "password", "", "", p}, false},
		{"ok tcp4", fields{"tcp4", "127.0.0.1:443", "", "cert.crt", "cert.key", "password", "", "", p}, false},
		{"ok tcp6", fields{"tcp6", ":443", "", "cert.crt", "cert.key", "", "", "", p}, false},
		{"ok unix", fields{"unix", "/tmp/sds.unix", "", "", "", "", "", "", p}, false},
		{"ok unixpacket", fields{"unix", "/tmp/sds.unix", "", "", "", "", "", "", p}, false},
		{"fail network", fields{"", ":443", "root.crt", "cert.crt", "cert.key", "", "", "", p}, true},
		{"fail network", fields{"foo", ":443", "root.crt", "cert.crt", "cert.key", "", "", "", p}, true},
		{"fail address", fields{"tcp", "", "root.crt", "cert.crt", "cert.key", "", "", "", p}, true},
		{"fail cert", fields{"tcp", ":443", "root.crt", "", "cert.key", "", "", "", p}, true},
		{"fail key", fields{"tcp", ":443", "root.crt", "cert.crt", "", "", "", "", p}, true},
		{"fail provisioner", fields{"tcp", ":443", "root.crt", "cert.crt", "cert.key", "", "", "", ProvisionerConfig{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				Network:               tt.fields.Network,
				Address:               tt.fields.Address,
				Root:                  tt.fields.Root,
				Certificate:           tt.fields.Certificate,
				CertificateKey:        tt.fields.CertificateKey,
				Password:              tt.fields.Password,
				AuthorizedIdentity:    tt.fields.AuthorizedIdentity,
				AuthorizedFingerprint: tt.fields.AuthorizedFingerprint,
				Provisioner:           tt.fields.Provisioner,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProvisionerConfig_Validate(t *testing.T) {
	type fields struct {
		Issuer   string
		KeyID    string
		Password string
		CaURL    string
		CaRoot   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"issuer", "key-id", "", "https://ca", "root.crt"}, false},
		{"ok password", fields{"issuer", "key-id", "password", "https://ca", "root.crt"}, false},
		{"fail issuer", fields{"", "key-id", "", "https://ca", "root.crt"}, true},
		{"fail key-id", fields{"issuer", "", "", "https://ca", "root.crt"}, true},
		{"fail ca-url", fields{"issuer", "key-id", "", "", "root.crt"}, true},
		{"fail ca-root", fields{"issuer", "key-id", "", "https://ca", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ProvisionerConfig{
				Issuer:   tt.fields.Issuer,
				KeyID:    tt.fields.KeyID,
				Password: tt.fields.Password,
				CaURL:    tt.fields.CaURL,
				CaRoot:   tt.fields.CaRoot,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ProvisionerConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfiguration(t *testing.T) {
	c := Config{
		Network:               "tcp",
		Address:               ":8443",
		Root:                  "/home/step/sds/root_ca.crt",
		Certificate:           "/home/step/sds/sds_server.crt",
		CertificateKey:        "/home/step/sds/sds_server_key",
		AuthorizedIdentity:    "envoy",
		AuthorizedFingerprint: "f46f6610bcb22787d5984343746de587abbe1dd9bbb3411129f6a79b87ff445f",
		Provisioner: ProvisionerConfig{
			Issuer: "sds@smallstep.com",
			KeyID:  "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
			CaURL:  "https://ca:9000",
			CaRoot: "/home/step/certs/root_ca.crt",
		},
		Logger: []byte(`{
        "format": "text"
    }`)}
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    Config
		wantErr bool
	}{
		{"ok", args{"testdata/sds.json"}, c, false},
		{"bad.json", args{"testdata/bad.json"}, Config{}, true},
		{"fail.json", args{"testdata/fail.json"}, Config{Network: "tcp"}, true},
		{"not found", args{"testdata/notFound.json"}, Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadConfiguration(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfiguration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadConfiguration() = %v, want %v", got, tt.want)
			}
		})
	}
}
