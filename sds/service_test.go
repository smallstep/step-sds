package sds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	rpc "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/x509util"
)

/*
type streamServer struct {
	grpc.ServerStream
	send func(r *v2.DiscoveryResponse) error
	recv func() (*v2.DiscoveryRequest, error)
}

func (s *streamServer) Send(r *v2.DiscoveryResponse) error {
	if s.send != nil {
		return s.send(r)
	}
	return nil
}

func (s *streamServer) Recv() (*v2.DiscoveryRequest, error) {
	if s.recv != nil {
		return s.recv()
	}
	return &v2.DiscoveryRequest{
		VersionInfo:   "versionInfo",
		Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
		ResourceNames: []string{"foo.smallstep.com"},
		TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		ResponseNonce: "nonce",
		ErrorDetail:   nil,
	}, nil
}
*/

func TestNew(t *testing.T) {
	ca := caServer(60 * time.Second)
	defer ca.Close()

	okConfig := Config{
		Provisioner: ProvisionerConfig{
			Issuer:   "sds@smallstep.com",
			KeyID:    "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
			Password: "password",
			CaURL:    ca.URL,
			CaRoot:   "testdata/root_ca.crt",
		},
		Logger: []byte("{}"),
	}

	failLoggerConfig := Config{
		Provisioner: ProvisionerConfig{
			Issuer:   "sds@smallstep.com",
			KeyID:    "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
			Password: "password",
			CaURL:    ca.URL,
			CaRoot:   "testdata/root_ca.crt",
		},
	}

	type args struct {
		c Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{okConfig}, false},
		{"fail provisioner", args{Config{}}, true},
		{"fail logger", args{failLoggerConfig}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == false {
				assert.NotNil(t, got)
			}
		})
	}
}

func TestService_StreamSecrets(t *testing.T) {
	ca := caServer(3 * time.Second)
	defer ca.Close()

	srv, err := New(Config{
		Provisioner: ProvisionerConfig{
			Issuer:   "sds@smallstep.com",
			KeyID:    "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
			Password: "password",
			CaURL:    ca.URL,
			CaRoot:   "testdata/root_ca.crt",
		},
		Logger: []byte("{}"),
	})
	assert.FatalError(t, err)
	defer srv.Stop()

	// Prepare server
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	srv.Register(s)
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(fmt.Sprintf("Server exited with error: %v", err))
		}
	}()

	// Prepare client
	dialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("localhost", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufconn: %v", err)
	}
	defer conn.Close()
	client := secret.NewSecretDiscoveryServiceClient(conn)

	tests := []struct {
		name    string
		req     *discovery.DiscoveryRequest
		wantErr bool
	}{
		{"ok", &discovery.DiscoveryRequest{
			VersionInfo:   "",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"foo.smallstep.com"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		}, false},
		{"ok trusted_ca", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"trusted_ca"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		}, false},
		{"ok validation_context", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"validation_context"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		}, false},
		{"ok multiple", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"foo.smallstep.com", "bar.smallstep.com", "trusted_ca", "validation_context"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		}, false},
		{"ok with error", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"foo.smallstep.com"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ErrorDetail:   &rpc.Status{Code: 123, Message: "an error"},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream, err := client.StreamSecrets(context.Background())
			if err != nil {
				t.Errorf("Service.StreamSecrets() error = %v", err)
				return
			}
			if err := stream.Send(tt.req); err != nil {
				t.Errorf("stream.Send() error = %v", err)
				return
			}

			// With error the client won't receive anything
			if tt.req.ErrorDetail != nil {
				return
			}

			got, err := stream.Recv()
			if (err != nil) != tt.wantErr {
				t.Errorf("stream.Recv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var hasServerCert bool
			if err == nil {
				assert.True(t, got.VersionInfo != "")
				assert.Len(t, len(tt.req.ResourceNames), got.Resources)
				assert.False(t, got.Canary)
				assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", got.TypeUrl)
				assert.Len(t, 64, got.Nonce)
				assert.Equals(t, &core.ControlPlane{Identifier: Identifier}, got.ControlPlane)
				for i, r := range got.Resources {
					assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", r.TypeUrl)
					var sec auth.Secret
					if assert.NoError(t, proto.Unmarshal(r.Value, &sec)) {
						assert.Equals(t, tt.req.ResourceNames[i], sec.Name)
						if isValidationContext(sec.Name) {
							assert.Type(t, &auth.Secret_ValidationContext{}, sec.Type)
						} else {
							hasServerCert = true
							assert.Type(t, &auth.Secret_TlsCertificate{}, sec.Type)
						}
					}
				}
			}

			old := got
			if hasServerCert {
				// ACK
				tt.req.VersionInfo = got.VersionInfo
				tt.req.ResponseNonce = got.Nonce
				if err := stream.Send(tt.req); err != nil {
					t.Errorf("stream.Send() error = %v", err)
					return
				}

				// New request
				tt.req.ResponseNonce = ""
				if err := stream.Send(tt.req); err != nil {
					t.Errorf("stream.Send() error = %v", err)
					return
				}

				for i := 0; i < 5; i++ {
					got, err := stream.Recv()
					if (err != nil) != tt.wantErr {
						t.Errorf("stream.Recv() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					assert.NotEquals(t, old, got)
					old = got

					assert.True(t, got.VersionInfo != "")
					assert.Len(t, len(tt.req.ResourceNames), got.Resources)
					assert.False(t, got.Canary)
					assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", got.TypeUrl)
					assert.Len(t, 64, got.Nonce)
					assert.Equals(t, &core.ControlPlane{Identifier: Identifier}, got.ControlPlane)
					for i, r := range got.Resources {
						assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", r.TypeUrl)
						var sec auth.Secret
						if assert.NoError(t, proto.Unmarshal(r.Value, &sec)) {
							assert.Equals(t, tt.req.ResourceNames[i], sec.Name)
							if isValidationContext(sec.Name) {
								assert.Type(t, &auth.Secret_ValidationContext{}, sec.Type)
							} else {
								assert.Type(t, &auth.Secret_TlsCertificate{}, sec.Type)
							}
						}
					}
				}
			}
		})
	}
}

func TestService_FetchSecrets(t *testing.T) {
	ca := caServer(60 * time.Second)
	defer ca.Close()

	srv, err := New(Config{
		Provisioner: ProvisionerConfig{
			Issuer:   "sds@smallstep.com",
			KeyID:    "oA1x2nV3yClaf2kQdPOJ_LEzTGw5ow4r2A5SWl3MfMg",
			Password: "password",
			CaURL:    ca.URL,
			CaRoot:   "testdata/root_ca.crt",
		},
		Logger: []byte("{}"),
	})
	assert.FatalError(t, err)
	defer srv.Stop()

	// Prepare server
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	srv.Register(s)
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(fmt.Sprintf("Server exited with error: %v", err))
		}
	}()

	// Prepare client
	dialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("localhost", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufconn: %v", err)
	}
	defer conn.Close()
	client := secret.NewSecretDiscoveryServiceClient(conn)

	tests := []struct {
		name    string
		req     *discovery.DiscoveryRequest
		wantErr bool
	}{
		{"ok", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"foo.smallstep.com"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ResponseNonce: "response-nonce",
		}, false},
		{"ok trusted_ca", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"trusted_ca"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ResponseNonce: "response-nonce",
		}, false},
		{"ok validation_context", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"validation_context"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ResponseNonce: "response-nonce",
		}, false},
		{"ok multiple", &discovery.DiscoveryRequest{
			VersionInfo:   "versionInfo",
			Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
			ResourceNames: []string{"foo.smallstep.com", "bar.smallstep.com", "trusted_ca", "validation_context"},
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ResponseNonce: "response-nonce",
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.FetchSecrets(context.Background(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.FetchSecrets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				assert.True(t, got.VersionInfo != "")
				assert.Len(t, len(tt.req.ResourceNames), got.Resources)
				assert.False(t, got.Canary)
				assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", got.TypeUrl)
				assert.Len(t, 64, got.Nonce)
				assert.Equals(t, &core.ControlPlane{Identifier: Identifier}, got.ControlPlane)
				for i, r := range got.Resources {
					assert.Equals(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", r.TypeUrl)
					var sec auth.Secret
					if assert.NoError(t, proto.Unmarshal(r.Value, &sec)) {
						assert.Equals(t, tt.req.ResourceNames[i], sec.Name)
						if isValidationContext(sec.Name) {
							assert.Type(t, &auth.Secret_ValidationContext{}, sec.Type)
						} else {
							assert.Type(t, &auth.Secret_TlsCertificate{}, sec.Type)
						}
					}
				}
			}
		})
	}
}

func TestService_validateRequest(t *testing.T) {
	req := &discovery.DiscoveryRequest{
		VersionInfo:   "versionInfo",
		Node:          &core.Node{Id: "node-id", Cluster: "node-cluster"},
		ResourceNames: []string{"foo.smallstep.com"},
		TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
		ResponseNonce: "response-nonce",
	}

	b, _ := pem.Decode([]byte(testCert))
	cert, err := x509.ParseCertificate(b.Bytes)
	assert.FatalError(t, err)
	fingerprint := x509util.Fingerprint(cert)

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: &credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})
	ctx2 := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})

	ctxNoPeer := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		},
	})

	type fields struct {
		isTCP                 bool
		authorizedIdentity    string
		authorizedFingerprint string
	}
	type args struct {
		ctx context.Context
		r   *discovery.DiscoveryRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok unix", fields{false, "", ""}, args{ctx, req}, false},
		{"ok tcp", fields{true, "", ""}, args{ctx, req}, false},
		{"ok authIdentity", fields{true, "foo.smallstep.com", ""}, args{ctx, req}, false},
		{"ok authFingerPrint", fields{true, "", fingerprint}, args{ctx, req}, false},
		{"ok authIdentity+authFingerPrint", fields{true, "foo.smallstep.com", fingerprint}, args{ctx, req}, false},
		{"ok authIdentity+authFingerPrint", fields{true, "foo.smallstep.com", fingerprint}, args{ctx2, req}, false},
		{"fail no peer", fields{true, "bar.smallstep.com", fingerprint}, args{context.Background(), req}, true},
		{"fail no peer certificate", fields{true, "bar.smallstep.com", fingerprint}, args{ctxNoPeer, req}, true},
		{"fail authIdentity", fields{true, "bar.smallstep.com", fingerprint}, args{ctx, req}, true},
		{"fail authFingerPrint", fields{true, "foo.smallstep.com", "123456"}, args{ctx, req}, true},
		{"fail authIdentity+authFingerPrint", fields{true, "bar.smallstep.com", "123456"}, args{ctx, req}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Service{
				isTCP:                 tt.fields.isTCP,
				authorizedIdentity:    tt.fields.authorizedIdentity,
				authorizedFingerprint: tt.fields.authorizedFingerprint,
			}
			if err := srv.validateRequest(tt.args.ctx, tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("Service.validateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
