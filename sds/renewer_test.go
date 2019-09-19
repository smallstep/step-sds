package sds

import (
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func Test_secretRenewer(t *testing.T) {
	srv := caServer(3 * time.Second)
	defer srv.Close()

	p := caProvisioner(srv)
	t1, err := p.Token("foo.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}

	sr, err := newSecretRenewer([]string{t1})
	if err != nil {
		t.Errorf("newSecretRenewer() error = %v", err)
		return
	}
	defer sr.Stop()

	// Get first certificate
	secs := sr.Secrets()
	assert.Len(t, 1, secs.Roots)
	assert.Len(t, 1, secs.Certificates)
	crt := secs.Certificates[0].Leaf
	assert.Equals(t, "foo.smallstep.com", crt.DNSNames[0])

	// Renew multiple times (once every second)
	for i := 0; i < 5; i++ {
		s := <-sr.RenewChannel()
		assert.Len(t, 1, s.Roots)
		assert.Len(t, 1, s.Certificates)
		assert.Equals(t, "foo.smallstep.com", s.Certificates[0].Leaf.DNSNames[0])
		assert.NotEquals(t, crt.SerialNumber, s.Certificates[0].Leaf.SerialNumber)
		crt = s.Certificates[0].Leaf
	}
}

func Test_newSecretRenewer(t *testing.T) {
	srv := caServer(60 * time.Second)
	defer srv.Close()

	p := caProvisioner(srv)

	t1, err := p.Token("foo.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}

	t2, err := p.Token(ValidationContextName)
	if err != nil {
		t.Fatal(err)
	}

	t3, err := p.Token(ValidationContextAltName)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		tokens []string
	}
	tests := []struct {
		name            string
		args            args
		lenCertificates int
		lenRoots        int
		wantErr         bool
	}{
		{"ok", args{[]string{t1}}, 1, 1, false},
		{"ok trusted_ca", args{[]string{t2}}, 0, 1, false},
		{"ok validation_context", args{[]string{t3}}, 0, 1, false},
		{"ok multiple", args{[]string{t1, t1}}, 2, 1, false},
		{"ok mixed", args{[]string{t1, t1, t2, t3}}, 2, 1, false},
		{"fail nil", args{nil}, 0, 0, true},
		{"fail empty", args{[]string{}}, 0, 0, true},
		{"fail bad token", args{[]string{"badtoken"}}, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSecretRenewer(tt.args.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("newSecretRenewer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				assert.Nil(t, got)
			} else {
				s := got.Secrets()
				assert.Len(t, tt.lenCertificates, s.Certificates)
				assert.Len(t, tt.lenRoots, s.Roots)
				got.Stop()
			}
		})
	}
}
