package rndc

import (
	"crypto"
	"fmt"
	"hash"
	"strings"

	"github.com/miekg/dns"
)

// Algorithm is a BIND RNDC TSIG algorithm identifier.
// Numeric values match the ISCCC protocol (not DNS algorithm numbers).
type Algorithm uint8

// HMAC algorithms used on the RNDC control channel.
const (
	MD5    Algorithm = 157
	SHA1   Algorithm = 161
	SHA224 Algorithm = 162
	SHA256 Algorithm = 163
	SHA384 Algorithm = 164
	SHA512 Algorithm = 165
)

func (a Algorithm) String() string {
	switch a {
	case MD5:
		return "md5"
	case SHA1:
		return "sha1"
	case SHA224:
		return "sha224"
	case SHA256:
		return "sha256"
	case SHA384:
		return "sha384"
	case SHA512:
		return "sha512"
	default:
		return fmt.Sprintf("algorithm(%d)", uint8(a))
	}
}

// TSIGName returns the miekg/dns TSIG algorithm name (for example dns.HmacSHA256).
func (a Algorithm) TSIGName() string {
	switch a {
	case MD5:
		return dns.HmacMD5
	case SHA1:
		return dns.HmacSHA1
	case SHA224:
		return dns.HmacSHA224
	case SHA256:
		return dns.HmacSHA256
	case SHA384:
		return dns.HmacSHA384
	case SHA512:
		return dns.HmacSHA512
	default:
		return ""
	}
}

func (a Algorithm) hash() (func() hash.Hash, error) {
	var h crypto.Hash
	switch a {
	case MD5:
		h = crypto.MD5 //nolint:gosec // MD5 is required by the RNDC protocol (hmd5).
	case SHA1:
		h = crypto.SHA1 //nolint:gosec // SHA-1 is required by the RNDC protocol.
	case SHA224:
		h = crypto.SHA224
	case SHA256:
		h = crypto.SHA256
	case SHA384:
		h = crypto.SHA384
	case SHA512:
		h = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", a)
	}
	if !h.Available() {
		return nil, fmt.Errorf("hash %s is not available", a)
	}
	return h.New, nil
}

func (a Algorithm) valid() bool {
	switch a {
	case MD5, SHA1, SHA224, SHA256, SHA384, SHA512:
		return true
	default:
		return false
	}
}

// ParseAlgorithm accepts names used by BIND, rndc-python, and miekg/dns
// (for example "sha256", "hmac-sha256", "HMAC-SHA256", "hmac-sha256.").
func ParseAlgorithm(s string) (Algorithm, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.TrimSuffix(n, ".")
	n = strings.TrimPrefix(n, "hmac-")
	switch n {
	case "md5", "md5.sig-alg.reg.int":
		return MD5, nil
	case "sha1":
		return SHA1, nil
	case "sha224":
		return SHA224, nil
	case "sha256":
		return SHA256, nil
	case "sha384":
		return SHA384, nil
	case "sha512":
		return SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", s)
	}
}
