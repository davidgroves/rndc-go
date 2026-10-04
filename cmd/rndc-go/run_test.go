package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/davidgroves/rndc-go"
)

type fakeClient struct {
	call func(command string) (rndc.Response, error)
}

func (f *fakeClient) Call(_ context.Context, command string) (rndc.Response, error) {
	if f.call != nil {
		return f.call(command)
	}
	return rndc.Response{"text": "ok"}, nil
}

func (f *fakeClient) Close() error { return nil }

func lookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func invoke(t *testing.T, args []string, env map[string]string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, lookup(env))
	return code, stdout.String(), stderr.String()
}

func TestHelp(t *testing.T) {
	code, _, errOut := invoke(t, []string{"--help"}, nil)
	if code != 0 {
		t.Fatalf("code %d %s", code, errOut)
	}
	if !strings.Contains(errOut, "RNDC server hostname") || !strings.Contains(errOut, "TSIG algorithm") || !strings.Contains(errOut, "COMMAND") {
		t.Fatalf("help: %s", errOut)
	}
}

func TestVersion(t *testing.T) {
	old := version
	version = "9.9.9-test"
	t.Cleanup(func() { version = old })
	code, out, _ := invoke(t, []string{"--version"}, nil)
	if code != 0 || !strings.Contains(out, "rndc-go") || !strings.Contains(out, "9.9.9-test") {
		t.Fatalf("%d %q", code, out)
	}
	code, out, _ = invoke(t, []string{"-V"}, nil)
	if code != 0 || !strings.Contains(out, "9.9.9-test") {
		t.Fatalf("short %d %q", code, out)
	}
}

func TestMissingCommand(t *testing.T) {
	code, _, errOut := invoke(t, []string{}, nil)
	if code == 0 || !strings.Contains(errOut, "COMMAND") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestMissingOptions(t *testing.T) {
	base := []string{"--port", "953", "--algorithm", "sha256", "--secret", "dGVzdHNlY3JldA==", "status"}
	code, _, errOut := invoke(t, base, nil)
	if code == 0 || !strings.Contains(errOut, "Missing --host") {
		t.Fatalf("host %d %s", code, errOut)
	}
	code, _, errOut = invoke(t, []string{"--host", "localhost", "--algorithm", "sha256", "--secret", "dGVzdHNlY3JldA==", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Missing --port") {
		t.Fatalf("port %d %s", code, errOut)
	}
	code, _, errOut = invoke(t, []string{"--host", "localhost", "--port", "953", "--secret", "dGVzdHNlY3JldA==", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Missing --algorithm") {
		t.Fatalf("algo %d %s", code, errOut)
	}
	code, _, errOut = invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Missing --secret") {
		t.Fatalf("secret %d %s", code, errOut)
	}
}

func TestEnvVarsUsed(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	var got rndc.Config
	dialFunc = func(_ context.Context, cfg rndc.Config) (rndcCaller, error) {
		got = cfg
		return &fakeClient{call: func(string) (rndc.Response, error) {
			return rndc.Response{"text": "server is running"}, nil
		}}, nil
	}
	code, out, errOut := invoke(t, []string{"status"}, map[string]string{
		"RNDC_HOST": "testhost", "RNDC_PORT": "953", "RNDC_ALGORITHM": "sha256", "RNDC_SECRET": "dGVzdHNlY3JldA==",
	})
	if code != 0 {
		t.Fatal(errOut)
	}
	if !strings.Contains(out, "server is running") {
		t.Fatal(out)
	}
	if got.Host != "testhost" || got.Port != 953 {
		t.Fatalf("%+v", got)
	}
}

func TestCLIOverridesEnv(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	var got rndc.Config
	dialFunc = func(_ context.Context, cfg rndc.Config) (rndcCaller, error) {
		got = cfg
		return &fakeClient{}, nil
	}
	code, _, errOut := invoke(t, []string{"--host", "clihost", "--port", "9953", "status"}, map[string]string{
		"RNDC_HOST": "envhost", "RNDC_PORT": "953", "RNDC_ALGORITHM": "sha256", "RNDC_SECRET": "dGVzdHNlY3JldA==",
	})
	if code != 0 {
		t.Fatal(errOut)
	}
	if got.Host != "clihost" || got.Port != 9953 {
		t.Fatalf("%+v", got)
	}
}

func TestCommandJoinAndText(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	var cmd string
	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{call: func(c string) (rndc.Response, error) {
			cmd = c
			return rndc.Response{"text": "zone info"}, nil
		}}, nil
	}
	code, out, errOut := invoke(t, []string{
		"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdHNlY3JldA==",
		"zonestatus", "example.com",
	}, nil)
	if code != 0 {
		t.Fatal(errOut)
	}
	if cmd != "zonestatus example.com" {
		t.Fatal(cmd)
	}
	if !strings.Contains(out, "zone info") {
		t.Fatal(out)
	}
}

func TestErrFieldAndResultCode(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{call: func(string) (rndc.Response, error) {
			return rndc.Response{"err": "zone not found"}, nil
		}}, nil
	}
	code, _, errOut := invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "zonestatus", "x.com"}, nil)
	if code == 0 || !strings.Contains(errOut, "zone not found") {
		t.Fatalf("%d %s", code, errOut)
	}

	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{call: func(string) (rndc.Response, error) {
			return rndc.Response{"text": "command failed", "result": "1"}, nil
		}}, nil
	}
	code, _, _ = invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "badcommand"}, nil)
	if code != 1 {
		t.Fatalf("code %d", code)
	}
}

func TestOtherFields(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{call: func(string) (rndc.Response, error) {
			return rndc.Response{"type": "response", "result": "0", "custom_field": "custom_value", "another": "data"}, nil
		}}, nil
	}
	code, out, errOut := invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "customcmd"}, nil)
	if code != 0 {
		t.Fatal(errOut)
	}
	if !strings.Contains(out, "custom_field: custom_value") || !strings.Contains(out, "another: data") {
		t.Fatal(out)
	}
	if strings.Contains(out, "type:") {
		t.Fatal(out)
	}
}

func TestCLIErrors(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return nil, rndc.ErrConnection
	}
	code, _, errOut := invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Connection error") {
		t.Fatalf("%d %s", code, errOut)
	}

	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return nil, errors.New("invalid secret key format")
	}
	code, _, errOut = invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "invalid!!!", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Configuration error") {
		t.Fatalf("%d %s", code, errOut)
	}

	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{call: func(string) (rndc.Response, error) {
			return nil, errors.New("Unexpected error")
		}}, nil
	}
	code, _, errOut = invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "status"}, nil)
	if code == 0 || !strings.Contains(errOut, "Unexpected error") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestAlgorithms(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	dialFunc = func(_ context.Context, _ rndc.Config) (rndcCaller, error) {
		return &fakeClient{}, nil
	}
	for _, a := range []string{
		"md5", "sha1", "sha224", "sha256", "sha384", "sha512",
		"hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512", "SHA256",
	} {
		code, _, errOut := invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", a, "--secret", "dGVzdA==", "status"}, nil)
		if code != 0 {
			t.Fatalf("%s: %s", a, errOut)
		}
	}
	code, _, errOut := invoke(t, []string{"--host", "localhost", "--port", "953", "--algorithm", "invalid-algo", "--secret", "dGVzdA==", "status"}, nil)
	if code == 0 || (!strings.Contains(errOut, "Invalid value") && !strings.Contains(errOut, "invalid-algo")) {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestTimeout(t *testing.T) {
	orig := dialFunc
	t.Cleanup(func() { dialFunc = orig })
	var got rndc.Config
	dialFunc = func(_ context.Context, cfg rndc.Config) (rndcCaller, error) {
		got = cfg
		return &fakeClient{}, nil
	}
	args := []string{"--host", "localhost", "--port", "953", "--algorithm", "sha256", "--secret", "dGVzdA==", "status"}
	code, _, errOut := invoke(t, args, nil)
	if code != 0 {
		t.Fatal(errOut)
	}
	if got.Timeout.Seconds() != 10 {
		t.Fatalf("default timeout %v", got.Timeout)
	}
	code, _, errOut = invoke(t, append([]string{"--timeout", "30"}, args...), nil)
	if code != 0 {
		t.Fatal(errOut)
	}
	if got.Timeout.Seconds() != 30 {
		t.Fatalf("custom %v", got.Timeout)
	}
}
