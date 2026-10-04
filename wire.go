package rndc

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // MD5 is part of the RNDC protocol.
	"crypto/sha1" //nolint:gosec // SHA-1 is part of the RNDC protocol.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

func init() {
	// Ensure hashes used by Algorithm.hash() are linked.
	_ = md5.Size
	_ = sha1.Size
	_ = sha256.Size
	_ = sha512.Size
}

const (
	dataTypeRaw  byte = 1
	dataTypeDict byte = 2
	dataTypeList byte = 3

	rndcVersion uint32 = 1
)

// dict is an insertion-ordered ISCCC dictionary.
type dict struct {
	keys []string
	vals map[string]value
}

type value struct {
	raw  []byte
	dict *dict
}

func newDict() *dict {
	return &dict{vals: make(map[string]value)}
}

func (d *dict) setRaw(key string, raw []byte) {
	if _, ok := d.vals[key]; !ok {
		d.keys = append(d.keys, key)
	}
	d.vals[key] = value{raw: append([]byte(nil), raw...)}
}

func (d *dict) setString(key, s string) {
	d.setRaw(key, []byte(s))
}

func (d *dict) setDict(key string, child *dict) {
	if _, ok := d.vals[key]; !ok {
		d.keys = append(d.keys, key)
	}
	d.vals[key] = value{dict: child}
}

func (d *dict) get(key string) (value, bool) {
	if d == nil {
		return value{}, false
	}
	v, ok := d.vals[key]
	return v, ok
}

func (d *dict) getDict(key string) *dict {
	v, ok := d.get(key)
	if !ok {
		return nil
	}
	return v.dict
}

func (d *dict) getRaw(key string) []byte {
	v, ok := d.get(key)
	if !ok {
		return nil
	}
	return v.raw
}

func marshalDict(d *dict, ignoreAuth bool) ([]byte, error) {
	if d == nil {
		return nil, nil
	}
	var out []byte
	for _, key := range d.keys {
		if ignoreAuth && key == "_auth" {
			continue
		}
		v := d.vals[key]
		if len(key) > 255 {
			return nil, fmt.Errorf("rndc: label too long")
		}
		out = append(out, byte(len(key)))
		out = append(out, key...)
		var payload []byte
		var typ byte
		if v.dict != nil {
			var err error
			payload, err = marshalDict(v.dict, false)
			if err != nil {
				return nil, err
			}
			typ = dataTypeDict
		} else {
			payload = v.raw
			typ = dataTypeRaw
		}
		if uint64(len(payload)) > 0xffffffff {
			return nil, fmt.Errorf("rndc: value too large")
		}
		var hdr [5]byte
		hdr[0] = typ
		binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
		out = append(out, hdr[:]...)
		out = append(out, payload...)
	}
	return out, nil
}

func unmarshalDict(data []byte) (*dict, error) {
	d := newDict()
	for len(data) > 0 {
		label, val, rest, err := parseElement(data)
		if err != nil {
			return nil, err
		}
		if _, exists := d.vals[label]; !exists {
			d.keys = append(d.keys, label)
		}
		d.vals[label] = val
		data = rest
	}
	return d, nil
}

func parseElement(data []byte) (label string, val value, rest []byte, err error) {
	if len(data) < 2 {
		return "", value{}, nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
	}
	labelLen := int(data[0])
	if len(data) < 1+labelLen+5 {
		return "", value{}, nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
	}
	label = string(data[1 : 1+labelLen])
	pos := 1 + labelLen
	typ := data[pos]
	pos++
	dataLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if len(data) < pos+dataLen {
		return "", value{}, nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
	}
	payload := data[pos : pos+dataLen]
	rest = data[pos+dataLen:]
	switch typ {
	case dataTypeRaw:
		return label, value{raw: append([]byte(nil), payload...)}, rest, nil
	case dataTypeDict:
		child, err := unmarshalDict(payload)
		if err != nil {
			return "", value{}, nil, err
		}
		return label, value{dict: child}, rest, nil
	case dataTypeList:
		return "", value{}, nil, fmt.Errorf("%w: list", ErrUnsupportedType)
	default:
		return "", value{}, nil, fmt.Errorf("%w: %d", ErrUnsupportedType, typ)
	}
}

func createHMAC(secret, data []byte, algo Algorithm) ([]byte, error) {
	newHash, err := algo.hash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newHash, secret)
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func verifyHMAC(secret, data []byte, algo Algorithm, remote []byte) bool {
	expected, err := createHMAC(secret, data, algo)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, remote)
}

func frameMessage(body []byte) []byte {
	// Length field is size of version (4) plus body.
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(body)+4))
	binary.BigEndian.PutUint32(out[4:8], rndcVersion)
	copy(out[8:], body)
	return out
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: failed to read response header: %v", ErrConnection, err)
	}
	msgLen := binary.BigEndian.Uint32(hdr[0:4])
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != rndcVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	if msgLen < 4 {
		return nil, fmt.Errorf("%w: invalid frame length", ErrConnection)
	}
	bodyLen := int(msgLen - 4)
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: failed to read complete response: %v", ErrConnection, err)
	}
	return body, nil
}

func packAuth(algo Algorithm, digest []byte) (key string, val []byte) {
	encoded := []byte(base64.StdEncoding.EncodeToString(digest))
	if algo == MD5 {
		out := make([]byte, 22)
		copy(out, encoded)
		return "hmd5", out
	}
	out := make([]byte, 1+88)
	out[0] = byte(algo)
	copy(out[1:], encoded)
	return "hsha", out
}

func unpackAuth(algo Algorithm, hashData []byte) ([]byte, bool) {
	var b64 []byte
	if algo == MD5 {
		b64 = trimNulls(hashData)
	} else {
		if len(hashData) < 2 {
			return nil, false
		}
		b64 = trimNulls(hashData[1:])
	}
	if len(b64) == 0 {
		return nil, false
	}
	out, err := decodeB64Python(b64)
	if err != nil {
		return nil, false
	}
	return out, true
}

func decodeB64Python(b64 []byte) ([]byte, error) {
	pad := 4 - (len(b64) % 4)
	padded := make([]byte, len(b64)+pad)
	copy(padded, b64)
	for i := len(b64); i < len(padded); i++ {
		padded[i] = '='
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(padded)))
	n, err := base64.StdEncoding.Decode(out, padded)
	if err != nil {
		n, err = base64.StdEncoding.Decode(out, b64)
		if err != nil {
			return nil, err
		}
	}
	return out[:n], nil
}

func trimNulls(b []byte) []byte {
	i := len(b)
	for i > 0 && b[i-1] == 0 {
		i--
	}
	return b[:i]
}

// hmacPayload returns the concatenation of every ISCCC element except _auth.
// That matches BIND's HMAC input and Python's serialize_dict(..., ignore_auth=True).
func hmacPayload(body []byte) ([]byte, error) {
	var out []byte
	data := body
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
		}
		labelLen := int(data[0])
		if len(data) < 1+labelLen+5 {
			return nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
		}
		label := string(data[1 : 1+labelLen])
		pos := 1 + labelLen + 1
		dataLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if len(data) < pos+dataLen {
			return nil, fmt.Errorf("%w: incomplete message data", ErrConnection)
		}
		end := pos + dataLen
		if label != "_auth" {
			out = append(out, data[:end]...)
		}
		data = data[end:]
	}
	return out, nil
}

func signDict(d *dict, secret []byte, algo Algorithm) ([]byte, error) {
	unsigned, err := marshalDict(d, true)
	if err != nil {
		return nil, err
	}
	digest, err := createHMAC(secret, unsigned, algo)
	if err != nil {
		return nil, err
	}
	key, val := packAuth(algo, digest)
	auth := newDict()
	auth.setRaw(key, val)
	d.setDict("_auth", auth)
	return marshalDict(d, false)
}

func verifyBody(secret []byte, algo Algorithm, body []byte, nonce []byte) (*dict, error) {
	msg, err := unmarshalDict(body)
	if err != nil {
		return nil, err
	}
	if len(nonce) > 0 {
		ctrl := msg.getDict("_ctrl")
		if ctrl == nil || !bytes.Equal(ctrl.getRaw("_nonce"), nonce) {
			return nil, ErrAuthentication
		}
	}
	auth := msg.getDict("_auth")
	if auth == nil {
		return nil, ErrAuthentication
	}
	authKey := "hsha"
	if algo == MD5 {
		authKey = "hmd5"
	}
	remote, ok := unpackAuth(algo, auth.getRaw(authKey))
	if !ok {
		return nil, ErrAuthentication
	}
	payload, err := hmacPayload(body)
	if err != nil {
		return nil, err
	}
	if !verifyHMAC(secret, payload, algo, remote) {
		return nil, ErrAuthentication
	}
	return msg, nil
}
