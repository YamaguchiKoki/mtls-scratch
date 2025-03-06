package mtoken

import (
	"crypto"
	"time"
)

const (
	alg = crypto.SHA256
)

var (
	timeFn = func() time.Time {
		return time.Now()
	}
)

type JWT struct {
	raw string
	header RawHeader
	claims RawClaims
	method Method
}

func NewJWT(header RawHeader, claims RawClaims, method Method) *JWT {
	header["alg"] = method.Name()
	return &JWT{
		header: header,
		claims: claims,
		method: method,
	}
}
