package mtoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

const ()

// ECDSA-SHA256
type ES256 struct {}

// Name returns alg name.
func (e ES256) Name() string {
	return "ES256"
}

// ECDSA署名の R, S 値を保持する構造体
type ecdsaSignature struct {
	R, S *big.Int
}

// 秘密鍵と署名対象の文字列を受け取り署名を生成する
func (e ES256) Sign(key interface{}, ss string) ([]byte, error) {
	// 秘密鍵をECDSA秘密鍵型にキャスト
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("予期しないキーの型です")
	}

	// 鍵長が256ビットであることを確認
	if k.Curve.Params().BitSize != 256 {
		return nil, errors.New("ES256には256ビットの鍵長が必要です")
	}

	// 1. デジタル署名の生成
	r, s, err := ecdsa.Sign(rand.Reader, k, execSha256(ss))
	if err != nil {
		return nil, errors.New("署名の生成に失敗しました")
	}

	// 2. R,S値をビッグエンディアン形式のバイト列に変換
	rByte := padding(r.Bytes(), 32)
	sByte := padding(s.Bytes(), 32)

	// 3. R,Sのバイト列を連結して署名を作成
	return append(rByte, sByte...), nil
}

// バイト列を指定された長さになるように左側にパディングする
func padding(b []byte, l int) []byte {
	if l <= len(b) {
		l = len(b)
	}
	pad := make([]byte, l-len(b))
	return append(pad, b...)
}

// 公開鍵と署名対象の文字列と署名を受け取り署名の検証を実行する
func (e ES256) Verify(key interface{}, ss string, sig []byte) error {
	// 公開鍵をECDSA公開鍵型にキャスト
	k, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("予期しないキーの型です")
	}

	// 署名からR,S値を取り出す（各32バイト）
	rByte := sig[:32]
	sByte := sig[32:]

	// バイト列を大きな整数に変換
	r := big.NewInt(0).SetBytes(rByte)
	s := big.NewInt(0).SetBytes(sByte)

	// 署名を検証
	status := ecdsa.Verify(k, execSha256(ss), r, s)
	if status != true {
		return errors.New("署名の検証に失敗しました")
	}
	return nil
}
