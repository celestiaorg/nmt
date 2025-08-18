package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestString verifies that id.String() returns the hexadecimal encoding of id.
func TestString(t *testing.T) {
	type testCase struct {
		id   ID
		want string
	}
	testCases := []testCase{
		{ID(""), ""},
		{ID("12345678"), "3132333435363738"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0}, "0000000000000000"},
		{[]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}, "aaaaaaaaaaaaaaaa"},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "0102030405060708"},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, tc.id.String())
	}
}

// Test_string verifies that string(id) returns the native string representation of id.
func Test_string(t *testing.T) {
	type testCase struct {
		id   ID
		want string
	}
	testCases := []testCase{
		{ID(""), ""},
		{ID("12345678"), "12345678"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0}, "\x00\x00\x00\x00\x00\x00\x00\x00"},
		{[]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "\x01\x02\x03\x04\x05\x06\a\b"},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, string(tc.id))
	}
}
