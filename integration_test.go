//go:build integration

package rndc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TEST_RNDC_SECRET is base64("secret-key-for-testing-only")
const testRNDCSecret = "c2VjcmV0LWtleS1mb3ItdGVzdGluZy1vbmx5"

const bind9Image = "internetsystemsconsortium/bind9:9.20"

func startBind9(t *testing.T) (host string, rndcPort, dnsPort int) {
	t.Helper()
	ctx := context.Background()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(wd, "testdata", "named.conf")
	zone := filepath.Join(wd, "testdata", "db.test.example")

	req := testcontainers.ContainerRequest{
		Image:        bind9Image,
		ExposedPorts: []string{"953/tcp", "53/tcp", "53/udp"},
		Cmd:          []string{"-g", "-c", "/etc/bind/named.conf"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: named, ContainerFilePath: "/etc/bind/named.conf", FileMode: 0o644},
			{HostFilePath: zone, ContainerFilePath: "/etc/bind/db.test.example", FileMode: 0o644},
		},
		WaitingFor: wait.ForLog("running").WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err = c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p953, err := c.MappedPort(ctx, "953/tcp")
	if err != nil {
		t.Fatal(err)
	}
	p53, err := c.MappedPort(ctx, "53/udp")
	if err != nil {
		t.Fatal(err)
	}
	return host, p953.Int(), p53.Int()
}

func integrationClient(t *testing.T, host string, port int) *Client {
	t.Helper()
	c, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		Algorithm:  SHA256,
		Secret:     testRNDCSecret,
		Timeout:    10 * time.Second,
		MaxRetries: 3,
		RetryDelay: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestIntegrationStatus(t *testing.T) {
	host, rndcPort, _ := startBind9(t)
	c := integrationClient(t, host, rndcPort)
	res, err := c.Call(context.Background(), "status")
	if err != nil {
		t.Fatal(err)
	}
	if res.Text() == "" {
		t.Fatal("empty status")
	}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.ServerIsUp {
		t.Fatalf("status parse: %+v", st)
	}
}

func TestIntegrationCommands(t *testing.T) {
	host, rndcPort, dnsPort := startBind9(t)
	c := integrationClient(t, host, rndcPort)
	ctx := context.Background()

	if res, err := c.Call(ctx, "reload"); err != nil || res.Err() != "" {
		t.Fatalf("reload %v %v", err, res)
	}
	if res, err := c.Call(ctx, "flush"); err != nil || res.Err() != "" {
		t.Fatalf("flush %v %v", err, res)
	}
	res, err := c.Call(ctx, "zonestatus test.example")
	if err != nil {
		t.Fatal(err)
	}
	if res.Text() == "" {
		t.Fatal("zonestatus")
	}
	if res, err := c.Call(ctx, "reconfig"); err != nil || res.Err() != "" {
		t.Fatalf("reconfig %v %v", err, res)
	}
	if res, err := c.Call(ctx, "recursing"); err != nil || res.Err() != "" {
		t.Fatalf("recursing %v %v", err, res)
	}
	if res, err := c.Call(ctx, "querylog on"); err != nil || res.Err() != "" {
		t.Fatalf("querylog on %v %v", err, res)
	}
	if res, err := c.Call(ctx, "querylog off"); err != nil || res.Err() != "" {
		t.Fatalf("querylog off %v %v", err, res)
	}
	if err := c.SetTraceLevel(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTraceLevel(ctx, 0); err != nil {
		t.Fatal(err)
	}

	// DNS-level check of the fixture zone.
	cl := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.test.example.", dns.TypeA)
	resp, _, err := cl.Exchange(m, net.JoinHostPort(host, strconv.Itoa(dnsPort)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("dns rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}

	res1, err := c.Call(ctx, "status")
	if err != nil || res1.Text() == "" {
		t.Fatal(err)
	}
	if _, err := c.Call(ctx, "reload"); err != nil {
		t.Fatal(err)
	}
	res3, err := c.Call(ctx, "status")
	if err != nil || res3.Text() == "" {
		t.Fatal(err)
	}
}

func TestIntegrationAuthFailures(t *testing.T) {
	host, rndcPort, _ := startBind9(t)
	cfg := Config{Host: host, Port: rndcPort, Algorithm: SHA256, Secret: "d3Jvbmctc2VjcmV0LWtleS1mb3ItdGVzdGluZw==", Timeout: 5 * time.Second, MaxRetries: 1}
	_, err := Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("wrong secret should fail")
	}
	cfg.Secret = testRNDCSecret
	cfg.Algorithm = SHA512
	_, err = Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("wrong algorithm should fail")
	}
}

func TestIntegrationContextManagerStyle(t *testing.T) {
	host, rndcPort, _ := startBind9(t)
	c, err := Dial(context.Background(), Config{
		Host: host, Port: rndcPort, Algorithm: SHA256, Secret: testRNDCSecret, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Call(context.Background(), "status")
	if err != nil || res.Text() == "" {
		t.Fatal(err)
	}
}
