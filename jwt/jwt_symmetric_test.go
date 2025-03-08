package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewJWTSymetric(t *testing.T) {
	type args struct {
		secret []byte
	}
	tests := []struct {
		name string
		args args
		want *Symetric
	}{
		{
			name: "Test with non-empty secret",
			args: args{secret: []byte("test")},
			want: &Symetric{secret: []byte("test")},
		},
		{
			name: "Test with empty secret",
			args: args{secret: []byte("")},
			want: &Symetric{secret: []byte("")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NewJWTSymetric(tt.args.secret)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJWTSymetric_Generate(t *testing.T) {
	tests := []struct {
		name    string
		arg     jwt.MapClaims
		want    string
		wantErr error
		mockFn  func() *Symetric
	}{
		{
			name: "Success",
			arg: jwt.MapClaims{
				"auth_id": "101",
				"email":   "email",
				"iss":     "test",
				"sub":     "test",
				"aud":     []string{"test"},
				"exp":     jwt.NewNumericDate(time.Date(2034, time.December, 1, 0, 0, 0, 0, time.Local)),
				"nbf":     jwt.NewNumericDate(time.Date(2024, time.December, 1, 0, 0, 0, 0, time.Local)),
				"iat":     jwt.NewNumericDate(time.Date(2024, time.December, 1, 0, 0, 0, 0, time.Local)),
			},
			wantErr: nil,
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdCJdLCJhdXRoX2lkIjoiMTAxIiwiZW1haWwiOiJlbWFpbCIsImV4cCI6MjA0ODUxODgwMCwiaWF0IjoxNzMyOTg2MDAwLCJpc3MiOiJ0ZXN0IiwibmJmIjoxNzMyOTg2MDAwLCJzdWIiOiJ0ZXN0In0.urXfGShpJOisNm29WkidShLG9oXOFZATyfhQkr_9Dlk",
			mockFn: func() *Symetric {
				return NewJWTSymetric([]byte("test"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			js := tt.mockFn()
			got, err := js.Generate(tt.arg)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJWTSymetric_Verify(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    jwt.Claims
		wantErr bool
		mockFn  func(t string) *Symetric
	}{
		{
			name:  "Success",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdCJdLCJhdXRoX2lkIjoiMTAxIiwiZW1haWwiOiJlbWFpbCIsImV4cCI6MjA0ODUxODgwMCwiaWF0IjoxNzMyOTg2MDAwLCJpc3MiOiJ0ZXN0IiwibmJmIjoxNzMyOTg2MDAwLCJzdWIiOiJ0ZXN0In0.urXfGShpJOisNm29WkidShLG9oXOFZATyfhQkr_9Dlk",
			want: jwt.MapClaims{
				"aud":     []any{"test"},
				"auth_id": "101",
				"email":   "email",
				"exp":     2.0485188e+09,
				"iat":     1.732986e+09,
				"iss":     "test",
				"nbf":     1.732986e+09,
				"sub":     "test",
			},
			wantErr: false,
			mockFn: func(t string) *Symetric {
				return NewJWTSymetric([]byte("test"))
			},
		},
		{
			name:    "ErrorExpired",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX2lkIjoiMTAxIiwiaXNzIjoidGVzdCIsInN1YiI6InRlc3QiLCJhdWQiOlsidGVzdCJdLCJleHAiOjExMDE4MzQwMDAsIm5iZiI6MTczMjk4NjAwMCwiaWF0IjoxNzMyOTg2MDAwfQ.UmgDfeLb-d_L7ZKq-33inhqoLR2jfXnmh3_jPaf9LoQ",
			want:    nil,
			wantErr: true,
			mockFn: func(t string) *Symetric {
				return NewJWTSymetric([]byte("test"))
			},
		},
		{
			name:    "ErrorVerify",
			token:   "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdCJdLCJhdXRoX2lkIjoiMTAxIiwiZW1haWwiOiJlbWFpbCIsImV4cCI6MjA0ODUxODgwMCwiaWF0IjoxNzMyOTg2MDAwLCJpc3MiOiJ0ZXN0IiwibmJmIjoxNzMyOTg2MDAwLCJzdWIiOiJ0ZXN0In0.-gL5xjPDItWnoc_mxiU3b5RDUQkiuM9GPE-mHbHnTR-P53twvbDuEtGCxoTfn_nYYdsUHn-4NUV5Qpxtauk6Hg",
			want:    nil,
			wantErr: true,
			mockFn: func(t string) *Symetric {
				return NewJWTSymetric([]byte("test"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			js := tt.mockFn(tt.token)
			got, err := js.Verify(tt.token)
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
