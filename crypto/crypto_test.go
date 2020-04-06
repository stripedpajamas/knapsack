package crypto

import (
	"bytes"
	"testing"
)

func TestDecrypt(t *testing.T) {
	k, err := NewKnapsack(8)
	if err != nil {
		t.Fatal(err)
	}

	msg := StringToBits("h")
	ct, err := Encrypt(k.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	if d := k.Decrypt(ct); !bytes.Equal(d, msg) {
		t.Errorf("wanted %v, got %v", msg, d)
	}
}

func isSuperincreasingSequence(arr []int64) bool {
	if len(arr) < 2 {
		return true
	}
	sum := arr[0]

	for i := 1; i < len(arr); i++ {
		if arr[i] <= sum {
			return false
		}
		sum += arr[i]
	}
	return true
}

func TestEncrypt(t *testing.T) {
	msg := []byte{1, 1, 0, 0, 1, 1, 0}
	pk := []int64{1, 2, 3, 4, 5, 6, 7}
	var expected int64 = 14 // 1 + 2 + 5 + 6 = 14
	actual, err := Encrypt(pk, msg)
	if err != nil {
		t.Fatal(err)
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

func TestInverse(t *testing.T) {
	type testCase struct {
		a        int64
		n        int64
		expected int64
	}
	testCases := []testCase{
		{a: 588, n: 881, expected: 442},
		{a: 3, n: 2000, expected: 667},
	}

	for idx, tc := range testCases {
		actual, err := inverse(tc.a, tc.n)
		if err != nil {
			t.Fatalf("encountered error with inputs %d, %d: %v", tc.a, tc.n, err)
		}
		if actual != tc.expected {
			t.Errorf("for test case #%d: wanted %v, got %v", idx, tc.expected, actual)
		}
	}
}

func TestSolveKnapsack(t *testing.T) {
	type testCase struct {
		weights  []int64
		s        int64
		expected []byte
	}
	testCases := []testCase{
		{weights: []int64{5, 10, 17, 33, 70}, s: 32, expected: []byte{1, 1, 1, 0, 0}},
	}

	for idx, tc := range testCases {
		actual := solveKnapsack(tc.weights, tc.s)
		if !bytes.Equal(actual, tc.expected) {
			t.Errorf("for test case #%d: wanted %v, got %v", idx, tc.expected, actual)
		}
	}
}
