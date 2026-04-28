package mcp

import (
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	data := []byte("hello world")
	encoded := encodeBase64(data)
	if encoded != "aGVsbG8gd29ybGQ=" {
		t.Errorf("unexpected encoding: %s", encoded)
	}
}
