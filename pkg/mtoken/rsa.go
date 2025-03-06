package mtoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// RSA-SHA256
type RS256 struct {}

// Name returns alg name.
func (r RS256) Name() string {
	return "RS256"
}

// 秘密鍵と署名対象の文字列を受け取り署名を生成する
func (r RS256) Sign(key interface{}, ss string) ([]byte, error) {
	// 秘密鍵をRSA秘密鍵型にキャスト
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("予期しないキーの型です")
	}
	// PKCS1v15形式でRSA署名を生成
	return rsa.SignPKCS1v15(rand.Reader, k, alg, execSha256(ss))
}

// 公開鍵と署名対象の文字列と署名を受け取り署名の検証を実行する
func (r RS256) Verify(key interface{}, ss string, sig []byte) error {
	// 公開鍵をRSA公開鍵型にキャスト
	k, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("予期しないキーの型です")
	}
	// PKCS1v15形式で署名を検証
	return rsa.VerifyPKCS1v15(k, alg, execSha256(ss), sig)
}

// 文字列データのSHA256ハッシュ値を計算する
func execSha256(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
