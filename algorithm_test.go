package rndc

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseAlgorithm(t *testing.T) {
	cases := []struct {
		in   string
		want Algorithm
	}{
		{"md5", MD5},
		{"sha1", SHA1},
		{"sha224", SHA224},
		{"sha256", SHA256},
		{"sha384", SHA384},
		{"sha512", SHA512},
		{"HMAC-SHA256", SHA256},
		{"hmac-sha256", SHA256},
		{"hmac-sha256.", SHA256},
		{dns.HmacSHA256, SHA256},
		{dns.HmacSHA512, SHA512},
		{dns.HmacMD5, MD5},
		{"  SHA1  ", SHA1},
	}
	for _, tc := range cases {
		got, err := ParseAlgorithm(tc.in)
		if err != nil {
			t.Fatalf("ParseAlgorithm(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseAlgorithm(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseAlgorithmInvalid(t *testing.T) {
	if _, err := ParseAlgorithm("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAlgorithmTSIGNameRoundTrip(t *testing.T) {
	for _, a := range []Algorithm{MD5, SHA1, SHA224, SHA256, SHA384, SHA512} {
		name := a.TSIGName()
		if name == "" {
			t.Fatalf("%s: empty TSIG name", a)
		}
		got, err := ParseAlgorithm(name)
		if err != nil {
			t.Fatalf("%s: ParseAlgorithm(%q): %v", a, name, err)
		}
		if got != a {
			t.Fatalf("%s: round trip got %s", a, got)
		}
		if a.String() == "" {
			t.Fatalf("empty String for %d", a)
		}
		if !a.valid() {
			t.Fatalf("%s not valid", a)
		}
	}
}

func TestUnknownAlgorithm(t *testing.T) {
	a := Algorithm(1)
	if a.valid() {
		t.Fatal("expected invalid")
	}
	if a.TSIGName() != "" {
		t.Fatal("expected empty TSIG name")
	}
	if a.String() != "algorithm(1)" {
		t.Fatalf("String=%q", a.String())
	}
}
