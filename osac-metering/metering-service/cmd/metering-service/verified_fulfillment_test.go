package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestVerifiedFulfillmentBundleRotation(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	serverCert := fixture.TLS.Certificates[0]
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw})
	fixture.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	caFile := filepath.Join(t.TempDir(), "bundle.pem")
	writeBundle := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(caFile, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeBundle(root)
	client := &verifiedFulfillmentConn{address: listener.Addr().String(), caFile: caFile}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.reload(ctx); err != nil {
		t.Fatalf("valid CA and hostname rejected: %v", err)
	}
	t.Cleanup(client.close)
	first := client.current.Load()
	firstHash := client.observedHash()
	if firstHash == "" {
		t.Fatal("successful probe did not record bundle hash")
	}
	if _, err := healthpb.NewHealthClient(client).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("verified client cannot call server: %v", err)
	}

	wrongRoot := makeTestCA(t)
	wrongAddress := "localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	for _, tc := range []struct {
		name    string
		bundle  []byte
		address string
	}{
		{"malformed", []byte("not PEM"), listener.Addr().String()},
		{"malformed suffix", append(append([]byte{}, root...), []byte("garbage")...), listener.Addr().String()},
		{"wrong root", wrongRoot, listener.Addr().String()},
		{"wrong SAN", append(root, '\n'), wrongAddress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeBundle(tc.bundle)
			client.address = tc.address
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer probeCancel()
			if err := client.reload(probeCtx); err == nil {
				t.Fatal("unverified replacement accepted")
			}
			if client.current.Load() != first || client.observedHash() != firstHash {
				t.Fatal("failed revision changed the last verified client or observed hash")
			}
			if _, err := healthpb.NewHealthClient(client).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
				t.Fatalf("last verified client was lost: %v", err)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if err := os.Remove(caFile); err != nil {
			t.Fatal(err)
		}
		if err := client.reload(ctx); err == nil {
			t.Fatal("missing CA file accepted")
		}
		if client.current.Load() != first || client.observedHash() != firstHash {
			t.Fatal("read failure changed the last verified client or observed hash")
		}
	})

	client.address = listener.Addr().String()
	writeBundle(append(append([]byte{}, root...), wrongRoot...))
	if err := client.reload(ctx); err != nil {
		t.Fatalf("valid replacement rejected: %v", err)
	}
	if client.current.Load() == first || client.observedHash() == firstHash {
		t.Fatal("verified revision did not atomically replace the client and hash")
	}
}

func makeTestCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wrong root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}
