package mtoken

import "errors"

// JWTヘッダーを表す型エイリアス
type RawHeader map[string]interface{}

func (r RawHeader) GetString(key string) (string, error) {
	if _, ok := r[key]; !ok {
		return "", errors.New("key not found")
	}
	if v, ok := r[key].(string); ok {
		return v, nil
	}
	return "", errors.New("given value is not string")
}
