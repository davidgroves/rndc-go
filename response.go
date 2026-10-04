package rndc

import "strconv"

// Response is the decoded `_data` section of an RNDC reply.
type Response map[string]string

// Text returns the BIND status/output text, if any.
func (r Response) Text() string {
	if r == nil {
		return ""
	}
	return r["text"]
}

// Err returns the RNDC error string, if any.
func (r Response) Err() string {
	if r == nil {
		return ""
	}
	return r["err"]
}

// ResultCode returns the numeric RNDC result, or 0 if absent/unparseable.
func (r Response) ResultCode() int {
	if r == nil {
		return 0
	}
	s := r["result"]
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
