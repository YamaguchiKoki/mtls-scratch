package mtoken

import "errors"

var (
	// ErrKeyPair は無効な秘密鍵の場合に使用されます
	ErrKeyPair = errors.New("無効な鍵ペアです")

	// ErrVerifyPoP は所有証明の検証に失敗した場合に発生します
	ErrVerifyPoP = errors.New("所有証明の検証に失敗しました")

	// ErrTokenExpire はトークンの有効期限が切れている場合に発生します
	ErrTokenExpire = errors.New("このトークンは有効期限が切れています")

	// ErrTokenIat はトークンがまだ使用可能でない場合に発生します
	ErrTokenIat = errors.New("このトークンはまだ使用できません")

	// ErrMutualTLSConnection は相互TLS接続が確立されていない場合に使用されます
	ErrMutualTLSConnection = errors.New("相互TLS接続が必要です")

	// ErrTokenStruct はトークン構造体が空の場合に使用されます
	ErrTokenStruct = errors.New("不明なトークン構造体タイプです")
)
