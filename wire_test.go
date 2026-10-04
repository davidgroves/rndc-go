package rndc

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSerializeParseRoundtrip(t *testing.T) {
	msg := newDict()
	ctrl := newDict()
	ctrl.SetString("_ser", "1")
	ctrl.SetString("_tim", "2")
	msg.SetDict("_ctrl", ctrl)
	data := newDict()
	data.SetString("msg", "hello")
	nested := newDict()
	nested.SetRaw("k", []byte("v"))
	data.SetDict("nested", nested)
	msg.SetDict("_data", data)
	auth := newDict()
	auth.SetRaw("token", []byte("abc"))
	msg.SetDict("_auth", auth)

	serialized, err := marshalDictForTest(msg, false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := unmarshalDictForTest(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.GetDict("_ctrl").GetRaw("_ser")) != "1" {
		t.Fatalf("ser=%q", parsed.GetDict("_ctrl").GetRaw("_ser"))
	}
	if string(parsed.GetDict("_data").GetRaw("msg")) != "hello" {
		t.Fatal("msg")
	}
	if string(parsed.GetDict("_data").GetDict("nested").GetRaw("k")) != "v" {
		t.Fatal("nested")
	}
	if string(parsed.GetDict("_auth").GetRaw("token")) != "abc" {
		t.Fatal("auth")
	}
}

func TestParseIncompleteData(t *testing.T) {
	_, err := unmarshalDictForTest([]byte{0x05, 's', 'h', 'o', 'r', 't'})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHMACCreateAndVerify(t *testing.T) {
	secret := []byte("secret-key")
	data := []byte("payload")
	digest, err := createHMACForTest(secret, data, SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyHMACForTest(secret, data, SHA256, digest) {
		t.Fatal("verify failed")
	}
	tampered := append([]byte{}, digest...)
	tampered[0] ^= 0xff
	if verifyHMACForTest(secret, data, SHA256, tampered) {
		t.Fatal("tampered should fail")
	}
}

func TestHMACAllAlgorithms(t *testing.T) {
	secret := []byte("secret-key")
	data := []byte("payload")
	for _, a := range []Algorithm{MD5, SHA1, SHA224, SHA256, SHA384, SHA512} {
		digest, err := createHMACForTest(secret, data, a)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if !verifyHMACForTest(secret, data, a, digest) {
			t.Fatalf("%s verify failed", a)
		}
	}
}

func TestUnsupportedListType(t *testing.T) {
	// label "x" (len 1), type LIST=3, length 0
	raw := []byte{0x01, 'x', dataTypeList, 0, 0, 0, 0}
	_, err := unmarshalDictForTest(raw)
	if err == nil {
		t.Fatal("expected list error")
	}
}

func TestPackAuthSizes(t *testing.T) {
	digest := bytes.Repeat([]byte{1}, 16)
	key, val := packAuthForTest(MD5, digest)
	if key != "hmd5" || len(val) != 22 {
		t.Fatalf("md5 %s %d", key, len(val))
	}
	digest32 := bytes.Repeat([]byte{2}, 32)
	key, val = packAuthForTest(SHA256, digest32)
	if key != "hsha" || len(val) != 89 || val[0] != byte(SHA256) {
		t.Fatalf("sha %s %d %d", key, len(val), val[0])
	}
}

func TestSignedStatusMatchesPythonGoldens(t *testing.T) {
	secret := []byte("test-secret")
	algs := []struct {
		name string
		algo Algorithm
	}{
		{"md5", MD5},
		{"sha1", SHA1},
		{"sha224", SHA224},
		{"sha256", SHA256},
		{"sha384", SHA384},
		{"sha512", SHA512},
	}
	for _, tc := range algs {
		t.Run(tc.name, func(t *testing.T) {
			msg := newDict()
			msg.setDict("_auth", newDict())
			ctrl := newDict()
			ctrl.setString("_ser", "1")
			ctrl.setString("_tim", "1700000000")
			ctrl.setString("_exp", "1700000060")
			ctrl.setString("_nonce", "n1")
			msg.setDict("_ctrl", ctrl)
			data := newDict()
			data.setString("type", "status")
			msg.setDict("_data", data)

			unsigned, err := marshalDict(msg, true)
			if err != nil {
				t.Fatal(err)
			}
			wantUnsigned, err := os.ReadFile(filepath.Join("testdata", "wire", "unsigned_status_"+tc.name+".hex"))
			if err != nil {
				t.Fatal(err)
			}
			wu, err := hex.DecodeString(string(bytes.TrimSpace(wantUnsigned)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unsigned, wu) {
				t.Fatalf("unsigned mismatch\n got %x\nwant %x", unsigned, wu)
			}

			signed, err := signDict(msg, secret, tc.algo)
			if err != nil {
				t.Fatal(err)
			}
			wantSigned, err := os.ReadFile(filepath.Join("testdata", "wire", "signed_status_"+tc.name+".hex"))
			if err != nil {
				t.Fatal(err)
			}
			ws, err := hex.DecodeString(string(bytes.TrimSpace(wantSigned)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(signed, ws) {
				t.Fatalf("signed mismatch\n got %x\nwant %x", signed, ws)
			}
			if _, err := verifyBody(secret, tc.algo, signed, []byte("n1")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGoldenVectors(t *testing.T) {
	dir := filepath.Join("testdata", "wire")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".hex" {
			continue
		}
		found++
		rawHex, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		rawHex = bytes.TrimSpace(rawHex)
		want, err := hex.DecodeString(string(rawHex))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		parsed, err := unmarshalDictForTest(want)
		if err != nil {
			t.Fatalf("%s parse: %v", e.Name(), err)
		}
		got, err := marshalDictForTest(parsed, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s roundtrip mismatch\n got %x\nwant %x", e.Name(), got, want)
		}
	}
	if found == 0 {
		t.Skip("no golden files yet")
	}
}

func TestIgnoreAuthOmitsAuth(t *testing.T) {
	msg := newDict()
	auth := newDict()
	auth.SetRaw("hsha", []byte("x"))
	msg.SetDict("_auth", auth)
	ctrl := newDict()
	ctrl.SetString("_ser", "1")
	msg.SetDict("_ctrl", ctrl)
	withAuth, _ := marshalDictForTest(msg, false)
	without, _ := marshalDictForTest(msg, true)
	if bytes.Equal(withAuth, without) {
		t.Fatal("expected auth omitted")
	}
	if !bytes.Contains(withAuth, []byte("_auth")) {
		t.Fatal("missing _auth")
	}
	if bytes.Contains(without, []byte("_auth")) {
		t.Fatal("auth should be omitted")
	}
}

func TestUnsupportedDataType(t *testing.T) {
	raw := []byte{0x01, 'x', 9, 0, 0, 0, 0}
	_, err := unmarshalDictForTest(raw)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFrameRoundtrip(t *testing.T) {
	body := []byte("hello")
	framed := frameMessage(body)
	r := bytes.NewReader(framed)
	got, err := readFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("%q", got)
	}
}

func TestReadFrameBadVersion(t *testing.T) {
	framed := frameMessage([]byte("x"))
	framed[7] = 9
	_, err := readFrame(bytes.NewReader(framed))
	if err == nil {
		t.Fatal("expected version error")
	}
}
