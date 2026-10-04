package rndc

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeRNDC struct {
	ln        net.Listener
	secret    []byte
	algo      Algorithm
	nonce     string
	handle    func(cmd string) map[string]string
	lastCmd   atomic.Value
	dropAfter atomic.Int32 // if >0, close after that many commands on a conn (including handshake)
}

func startFakeRNDC(t *testing.T, secret []byte, algo Algorithm, handle func(cmd string) map[string]string) *fakeRNDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRNDC{ln: ln, secret: secret, algo: algo, nonce: "test-nonce", handle: handle}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeRNDC) addr() string { return f.ln.Addr().String() }

func (f *fakeRNDC) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.addr())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	_, _ = fmtSscanf(portStr, &port)
	return host, mustAtoi(portStr)
}

func fmtSscanf(s string, n *int) (int, error) {
	*n = mustAtoi(s)
	return 1, nil
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func (f *fakeRNDC) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handleConn(conn)
	}
}

func (f *fakeRNDC) handleConn(conn net.Conn) {
	defer conn.Close()
	var count int32
	for {
		body, err := readFrame(conn)
		if err != nil {
			return
		}
		msg, err := verifyBody(f.secret, f.algo, body, nil)
		if err != nil {
			return
		}
		count++
		cmd := string(msg.getDict("_data").getRaw("type"))
		f.lastCmd.Store(cmd)
		data := map[string]string{"result": "0"}
		if cmd != "null" && f.handle != nil {
			data = f.handle(cmd)
			if data == nil {
				data = map[string]string{"result": "0"}
			}
		}
		if err := f.reply(conn, data); err != nil {
			return
		}
		limit := f.dropAfter.Load()
		if limit > 0 && count >= limit {
			return
		}
	}
}

func (f *fakeRNDC) reply(w io.Writer, data map[string]string) error {
	msg := newDict()
	msg.setDict("_auth", newDict())
	ctrl := newDict()
	ctrl.setString("_ser", "1")
	ctrl.setString("_tim", "1")
	ctrl.setString("_exp", "999999")
	ctrl.setString("_nonce", f.nonce)
	msg.setDict("_ctrl", ctrl)
	payload := newDict()
	for k, v := range data {
		payload.setString(k, v)
	}
	msg.setDict("_data", payload)
	body, err := signDict(msg, f.secret, f.algo)
	if err != nil {
		return err
	}
	_, err = w.Write(frameMessage(body))
	return err
}

func testSecretB64() string {
	return base64.StdEncoding.EncodeToString([]byte("test-secret"))
}

func testCfg(host string, port int) Config {
	return Config{
		Host:       host,
		Port:       port,
		Algorithm:  SHA256,
		Secret:     testSecretB64(),
		Timeout:    2 * time.Second,
		MaxRetries: 1,
		RetryDelay: 10 * time.Millisecond,
	}
}

func TestCallDecodesBytes(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(_ string) map[string]string {
		return map[string]string{"result": "ok", "text": "server is up"}
	})
	host, port := f.hostPort(t)
	ctx := context.Background()
	c, err := Dial(ctx, testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Call(ctx, "status")
	if err != nil {
		t.Fatal(err)
	}
	if res["result"] != "ok" || res.Text() != "server is up" {
		t.Fatalf("%v", res)
	}
}

func TestPrepareMessageContainsAuth(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	c := &Client{cfg: Config{Algorithm: SHA256, Timeout: time.Second}, secret: secret, nonce: []byte("nonce"), serial: 1}
	frame, err := c.prepare(map[string]string{"type": "status"})
	if err != nil {
		t.Fatal(err)
	}
	body := frame[8:]
	parsed, err := unmarshalDict(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.getDict("_ctrl").getRaw("_nonce")) != "nonce" {
		t.Fatal("nonce")
	}
	if parsed.getDict("_auth") == nil {
		t.Fatal("auth")
	}
	if string(parsed.getDict("_data").getRaw("type")) != "status" {
		t.Fatal("type")
	}
}

func TestBadHMAC(t *testing.T) {
	good, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, good, SHA256, nil)
	host, port := f.hostPort(t)
	cfg := testCfg(host, port)
	cfg.Secret = base64.StdEncoding.EncodeToString([]byte("other-secret-key!!"))
	_, err := Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected auth/connection error")
	}
}

func TestWrongAlgorithm(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, nil)
	host, port := f.hostPort(t)
	cfg := testCfg(host, port)
	cfg.Algorithm = SHA512
	_, err := Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNonceMismatch(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(string) map[string]string {
		return map[string]string{"result": "0"}
	})
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.mu.Lock()
	c.nonce = []byte("wrong")
	c.mu.Unlock()
	_, err = c.Call(context.Background(), "status")
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("got %v", err)
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(string) map[string]string {
		return map[string]string{"text": "ok", "result": "0"}
	})
	f.dropAfter.Store(2) // handshake + first command, then drop
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Call(context.Background(), "status"); err != nil {
		t.Fatal(err)
	}
	// connection dropped; next Call should reconnect
	if _, err := c.Call(context.Background(), "status"); err != nil {
		t.Fatal(err)
	}
}

func TestContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// Accept but never speak RNDC.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(2 * time.Second)
				c.Close()
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	cfg := testCfg(host, mustAtoi(portStr))
	cfg.Timeout = 50 * time.Millisecond
	cfg.MaxRetries = 1
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err = Dial(ctx, cfg)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestAddZoneCommandAndExists(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(cmd string) map[string]string {
		if strings.Contains(cmd, "already.com") {
			return map[string]string{"result": "16", "err": "already exists"}
		}
		return map[string]string{"result": "0"}
	})
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.AddZone(ctx, "new.example"); err != nil {
		t.Fatal(err)
	}
	cmd, _ := f.lastCmd.Load().(string)
	if !strings.Contains(cmd, "addzone new.example IN") || !strings.Contains(cmd, "template primary") {
		t.Fatalf("cmd %q", cmd)
	}
	err = c.AddZone(ctx, "already.com")
	if !errors.Is(err, ErrZoneAlreadyExists) {
		t.Fatalf("got %v", err)
	}
	if err := c.AddZone(ctx, ""); err == nil {
		t.Fatal("empty zone should be invalid")
	}
}

func TestDelZoneAndNotify(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(cmd string) map[string]string {
		if strings.Contains(cmd, "missing.com") {
			return map[string]string{"result": "20", "err": "not found"}
		}
		return map[string]string{"result": "0"}
	})
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.DelZone(ctx, "gone.example", WithClean(), WithClass(dns.ClassCHAOS), WithView("internal")); err != nil {
		t.Fatal(err)
	}
	cmd, _ := f.lastCmd.Load().(string)
	if !strings.Contains(cmd, "delzone -clean gone.example CH internal") {
		t.Fatalf("cmd %q", cmd)
	}
	if err := c.DelZone(ctx, "missing.com"); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := c.Notify(ctx, "gone.example", WithView("internal")); err != nil {
		t.Fatal(err)
	}
	cmd, _ = f.lastCmd.Load().(string)
	if cmd != "notify gone.example IN internal" {
		t.Fatalf("notify %q", cmd)
	}
	if err := c.Notify(ctx, "missing.com"); !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestSetTraceLevel(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, nil)
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	if err := c.SetTraceLevel(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTraceLevel(ctx, -1); err == nil {
		t.Fatal("expected bounds error")
	}
	if err := c.SetTraceLevel(ctx, 100); err == nil {
		t.Fatal("expected bounds error")
	}
}

func TestStatusHelper(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(string) map[string]string {
		return map[string]string{"text": sampleStatusText, "result": "0"}
	})
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.ServerIsUp {
		t.Fatal("expected up")
	}
}

func TestDialMissingHost(t *testing.T) {
	_, err := Dial(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResponseHelpers(t *testing.T) {
	var r Response
	if r.Text() != "" || r.Err() != "" || r.ResultCode() != 0 {
		t.Fatal("nil")
	}
	r = Response{"result": "20", "err": "not found", "text": "x"}
	if r.ResultCode() != 20 || r.Err() != "not found" || r.Text() != "x" {
		t.Fatal(r)
	}
}

func TestConcurrentCallsSafe(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString(testSecretB64())
	f := startFakeRNDC(t, secret, SHA256, func(string) map[string]string {
		return map[string]string{"result": "0"}
	})
	host, port := f.hostPort(t)
	c, err := Dial(context.Background(), testCfg(host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Call(context.Background(), "status")
		}()
	}
	wg.Wait()
}

func TestUnsupportedVersion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readFrame(conn)
		bad := frameMessage([]byte("x"))
		bad[7] = 2
		_, _ = conn.Write(bad)
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	cfg := testCfg(host, mustAtoi(portStr))
	cfg.MaxRetries = 1
	_, err = Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
}
