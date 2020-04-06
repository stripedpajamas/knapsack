package crypto

import (
	"bytes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	msg := []byte{1, 1, 0, 0, 1, 1, 0}
	pk := []int64{1, 2, 3, 4, 5, 6, 7}
	var expected int64 = 14 // 1 + 2 + 5 + 6 = 14
	actual, err := Encrypt(pk, msg)
	if err != nil {
		t.Error(err)
	}
	if actual != expected {
		t.Errorf("wanted %v, got %v", expected, actual)
	}
}

func TestStringToBits(t *testing.T) {
	expected := []byte{0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1}
	actual := StringToBits("hello")
	if !bytes.Equal(actual, expected) {
		t.Errorf("wanted %v, got %v", expected, actual)
	}
}
