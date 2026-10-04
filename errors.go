package rndc

import "errors"

var (
	// ErrAuthentication is returned when HMAC verification fails or the nonce is wrong.
	ErrAuthentication = errors.New("rndc: authentication failed")
	// ErrConnection is returned when the TCP session cannot be established or I/O fails.
	ErrConnection = errors.New("rndc: connection failed")
	// ErrZoneNotFound is returned when BIND reports that a zone is missing.
	ErrZoneNotFound = errors.New("rndc: zone not found")
	// ErrZoneAlreadyExists is returned when BIND reports that a zone already exists.
	ErrZoneAlreadyExists = errors.New("rndc: zone already exists")
	// ErrUnsupportedVersion is returned when the RNDC framing version is not 1.
	ErrUnsupportedVersion = errors.New("rndc: unsupported message version")
	// ErrInvalidZoneName is returned when a zone name is not a valid domain name.
	ErrInvalidZoneName = errors.New("rndc: invalid zone name")
	// ErrUnsupportedType is returned when a wire value uses an unknown ISCCC type.
	ErrUnsupportedType = errors.New("rndc: unsupported data type")
)
