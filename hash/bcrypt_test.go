package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestNewBcryptHash(t *testing.T) {
	type args struct {
		cost int
	}
	tests := []struct {
		name string
		args args
		want *BcryptHash
	}{
		{
			name: "Success",
			args: args{},
			want: &BcryptHash{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NewBcryptHash(tt.args.cost)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBcryptHash_Hash(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
		h       *BcryptHash
	}{
		{
			name:    "Success",
			args:    args{str: "hash"},
			want:    []byte("$2a$10$IWswZQf54RI4d08qs80OrOZovvu8HuqwBmy4swqAfy67kzLgqhAHW"),
			wantErr: nil,
			h:       &BcryptHash{},
		},
		{
			name:    "Error",
			args:    args{str: "$2a$10$IWswZQf54RI4d08qs80OrOZovvu8HuqwBmy4swqAfy67kzLgqhAHW1111111111111"},
			want:    nil,
			wantErr: bcrypt.ErrPasswordTooLong,
			h:       &BcryptHash{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.h.Hash(tt.args.str)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, len(tt.want), len(got))
		})
	}
}

func TestBcryptHash_Verify(t *testing.T) {
	type args struct {
		hashed string
		str    string
	}
	tests := []struct {
		name string
		args args
		want bool
		h    *BcryptHash
	}{
		{
			name: "Success",
			args: args{hashed: "$2a$10$IWswZQf54RI4d08qs80OrOZovvu8HuqwBmy4swqAfy67kzLgqhAHW", str: "hash"},
			want: true,
			h:    &BcryptHash{},
		},
		{
			name: "Error",
			args: args{hashed: "$2a$10$", str: "hash"},
			want: false,
			h:    &BcryptHash{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.h.Verify(tt.args.hashed, tt.args.str)
			assert.Equal(t, tt.want, got)
		})
	}
}
