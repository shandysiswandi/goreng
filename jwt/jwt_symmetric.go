package jwt

import (
	"crypto"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var _ JWT = &Symetric{}

type Symetric struct {
	secret []byte
}

func NewJWTSymetric(secret []byte) *Symetric {
	return &Symetric{secret: secret}
}

func (js *Symetric) Generate(c jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(js.secret)
}

func (js *Symetric) Verify(token string) (jwt.Claims, error) {
	tkn, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if sm, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || sm.Hash != crypto.SHA256 {
			return nil, jwt.ErrTokenSignatureInvalid
		}

		return js.secret, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrTokenExpired
	}

	if err != nil {
		return nil, err
	}

	return tkn.Claims, nil
}
