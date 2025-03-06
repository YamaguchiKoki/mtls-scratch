package mtoken

import (
	"errors"
	"time"
)

// JWTのクレーム（データ）を保持するマップ型
type RawClaims map[string]interface{}

// 指定されたキーの値を整数(int64)として取得する
func (r RawClaims) GetInt64(key string) (int64, error) {
	if _, ok := r[key]; !ok {
		return 0, errors.New("クレームにキーが存在しません")
	}
	// 値の型に応じて適切な変換を行う
	switch v := r[key].(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	}
	return 0, errors.New("値の型が一致しません")
}

// 有効期限（exp）の検証を行う
func (r RawClaims) VerifyExp() bool {
	exp, err := r.GetInt64("exp")
	if err != nil {
		return false
	}
	return exp > timeFn().Unix()
}

// トークン発行時刻（iat）の検証を行う
func (r RawClaims) VerifyIat() bool {
	iat, err := r.GetInt64("iat")
	if err != nil {
		return false
	}
	return iat <= timeFn().Unix()
}

// 証明書のSHA-256フィンガープリントを取得する
// 証明書確認（cnf）クレームからx5t#S256の値を取得する
func (r RawClaims) GetX5tS256() string {
	if cnf, ok := r["cnf"].(map[string]interface{}); ok {
		if s256, ok := cnf["x5t#S256"]; ok {
			if v, ok := s256.(string); ok {
				return v
			}
		}
	}
	return ""
}

// 新しいクレームを作成する
// 時間に関するクレーム（iat, exp）と証明書のフィンガープリントを追加する
func NewClaims(claims RawClaims, thumbprint string) (RawClaims, error) {

	claims = addTimeClaims(claims)

	var err error
	claims, err = addX5tS256(claims, thumbprint)
	if err != nil {
		return claims, err
	}

	return claims, nil
}

// 時間に関するクレーム（iat, exp）を追加する
// - iat（発行時刻）が存在しない場合、現在時刻を設定
// - exp（有効期限）が存在しない場合、発行時刻から1時間後を設定
func addTimeClaims(claims RawClaims) RawClaims {
	now := timeFn()

	if _, err := claims.GetInt64("iat"); err != nil {
		claims["iat"] = now.Unix()
	}

	if _, err := claims.GetInt64("exp"); err != nil {
		iat := now

		if v, err := claims.GetInt64("exp"); err == nil {
			iat = time.Unix(v, 0)
		}
		claims["exp"] = iat.Add(time.Hour).Unix()
	}
	return claims
}

// 証明書のフィンガープリントをクレームに追加する
// - cnfクレームが存在しない場合、新規作成
// - x5t#S256が存在しない場合、フィンガープリントを設定
// - cnfの型が不正な場合はエラーを返す
func addX5tS256(claims RawClaims, thumbprint string) (RawClaims, error) {
	if _, ok := claims["cnf"]; !ok {
		claims["cnf"] = RawClaims{
			"x5t#S256": thumbprint,
		}
		return claims, nil
	}

	if cnf, ok := claims["cnf"].(RawClaims); ok {
		if _, s256 := cnf["x5t#S256"]; !s256 {
			cnf["x5t#S256"] = thumbprint
			return claims, nil
		}
		return claims, nil
	}
	return nil, errors.New("cnf must be RawClaims")
}
