// Package rndc is a Go client library for ISC BIND's Remote Name Daemon Control (RNDC) protocol.
//
// It speaks the ISCCC control-channel framing used by named, authenticating
// messages with HMAC (MD5 through SHA-512). DNS class constants and zone-name
// checks come from miekg/dns; the control-channel HMAC itself uses crypto/hmac.
package rndc
