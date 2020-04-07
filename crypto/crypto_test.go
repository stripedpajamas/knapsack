package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

func TestDecrypt(t *testing.T) {
	k, err := NewKnapsack(100)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(
		"Knapsack:\n\tPub key: %v\n\tPriv key: %v\n\tM: %v\n\tW: %v\n\tW^-1: %v\n",
		k.PublicKey,
		k.privateKey,
		k.m,
		k.w,
		k.wi,
	)

	msg := "hello world"
	ct, err := EncryptString(k.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Ciphertext: %v\n", ct)
	t.Logf("Ciphertext bit-length: %v\n", len(ct)*8)

	pubBitLen := 0
	privBitLen := 0
	for i, n := range k.PublicKey {
		pubBitLen += len(n.Bytes()) * 8
		privBitLen += len(k.privateKey[i].Bytes()) * 8
	}
	t.Logf("Public key bit-length: %v\n", pubBitLen)
	t.Logf("Private key bit-length: %v\n", privBitLen)

	// knapsack is len 100, "hello world" is 88 bits (11 bytes * 8)
	// so using HasPrefix instead of Equals to account for the padding
	if d := k.DecryptBytes(ct); !bytes.HasPrefix(d, []byte(msg)) {
		t.Errorf("wanted %v, got %v", msg, d)
	}
}

func TestEncryptString(t *testing.T) {
	msg := "h" // 01101000
	pk := intsToBigs([]int64{1, 2, 3, 4, 5, 6, 7, 8})
	expected := big.NewInt(10).Bytes() // 2 + 3 + 5 = 10
	actual, err := EncryptString(pk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("wanted %v, got %v", expected, actual)
	}
}

func TestStringToBits(t *testing.T) {
	expected := []byte{0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1}
	actual := stringToBits("hello")
	if !bytes.Equal(actual, expected) {
		t.Errorf("wanted %v, got %v", expected, actual)
	}
}

func TestBitsToBytes(t *testing.T) {
	bits := []byte{0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1}
	bytez := []byte("hello")
	if actual := bitsToBytes(bits); !bytes.Equal(actual, bytez) {
		t.Errorf("wanted %v, got %v", bytez, actual)
	}
}

func TestSolveKnapsack(t *testing.T) {
	type testCase struct {
		weights  []*big.Int
		s        *big.Int
		expected []byte
	}
	testCases := []testCase{
		{
			weights:  intsToBigs([]int64{5, 10, 17, 33, 70}),
			s:        big.NewInt(32),
			expected: []byte{1, 1, 1, 0, 0}},
	}

	for idx, tc := range testCases {
		actual := solveKnapsack(tc.weights, tc.s)
		if !bytes.Equal(actual, tc.expected) {
			t.Errorf("for test case #%d: wanted %v, got %v", idx, tc.expected, actual)
		}
	}
}

func intsToBigs(ints []int64) []*big.Int {
	out := make([]*big.Int, len(ints))
	for i, n := range ints {
		out[i] = big.NewInt(n)
	}
	return out
}
