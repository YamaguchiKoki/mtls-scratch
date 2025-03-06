package mtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// HMAC-SHA256
type HS256 struct {}

func (r HS256) Name() string {
	return "HS256"
}

// 秘密鍵と署名対象の文字列を受け取り署名を生成する
func (r HS256) Sign(key interface{}, ss string) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, errors.New("予期しないキーの型です")
	}
	hasher := hmac.New(sha256.New, k)
	hasher.Write([]byte(ss))
	return hasher.Sum(nil), nil
}

// 秘密鍵と署名対象の文字列と署名を受け取り署名の検証を実行する
func (r HS256) Verify(key interface{}, ss string, sig []byte) error {
	k, ok := key.([]byte)
	if !ok {
		return errors.New("予期しないキーの型です")
	}
	hasher := hmac.New(sha256.New, k)
	hasher.Write([]byte(ss))
	// 生成したハッシュ受け取った署名を比較
	if !hmac.Equal(hasher.Sum(nil), sig) {
		return errors.New("署名の検証に失敗しました")
	}
	return nil
}
