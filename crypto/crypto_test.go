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

	msg := StringToBits("hello world")
	ct, err := Encrypt(k.PublicKey, msg)
	t.Log(ct)
	if err != nil {
		t.Fatal(err)
	}

	// knapsack is len 100, "hello world" is 88 bits (11 bytes * 8)
	expected := append(msg, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)

	if d := k.Decrypt(ct); !bytes.Equal(d, expected) {
		t.Errorf("wanted %v, got %v", msg, d)
	}
}

func TestEncrypt(t *testing.T) {
	msg := []byte{1, 1, 0, 0, 1, 1, 0}
	pk := intsToBigs([]int64{1, 2, 3, 4, 5, 6, 7})
	expected := big.NewInt(14) // 1 + 2 + 5 + 6 = 14
	actual, err := Encrypt(pk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Cmp(expected) != 0 {
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
