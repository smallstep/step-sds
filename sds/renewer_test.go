package sds

import (
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func Test_newSecretRenewer(t *testing.T) {
	srv := caServer(15 * time.Second)
	defer srv.Close()

	p := caProvisioner(srv)
	t1, err := p.Token("foo.smallstep.com")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		tokens []string
	}
	tests := []struct {
		name    string
		args    args
		want    *secretRenewer
		wantErr bool
	}{
		{"ok", args{[]string{t1}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSecretRenewer(tt.args.tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("newSecretRenewer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			secrets := got.Secrets()
			assert.Len(t, 1, secrets.Roots)
			assert.Len(t, 1, secrets.Certificates)
			sn := secrets.Certificates[0].Leaf.SerialNumber
			// Renew
			s := <-got.RenewChannel()
			assert.Len(t, 1, s.Roots)
			assert.Len(t, 1, s.Certificates)
			assert.NotEquals(t, sn, s.Certificates[0].Leaf.SerialNumber)
		})
	}
}
