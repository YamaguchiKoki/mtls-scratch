package mtoken

import "errors"

type Method interface {
	Name() string
	Sign(interface{}, string) ([]byte, error)
	Verify(interface{}, string, []byte) error
}

func ParseMethod(name string) (Method, error) {
	switch name {
		case "HS256":
		return HS256{}, nil
	case "RS256":
		return RS256{}, nil
	case "ES256":
		return ES256{}, nil
	default:
		return nil, errors.New("Unsupported error")
	}
}


