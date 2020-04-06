package crypto

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
)

// Knapsack contains the private data used to generate the public key and decrypt messages
type Knapsack struct {
	PublicKey  []int64
	privateKey []int64
	m          int64 // modulus
	w          int64 // random mutating constant
	wi         int64 // inverse of w
}

// NewKnapsack auto generates private knapsack params
func NewKnapsack(keyLength int) (*Knapsack, error) {
	if keyLength > 56 { // since we aren't using big.Int yet, we're a little limited here
		return nil, errors.New("key length must be <= 56")
	}
	// private sequence should begin at around 2^n (n is the sequence length)
	// and should end around 2^2n
	min := math.Pow(2, float64(keyLength))
	// max := math.Pow(2, float64(2*keyLength))

	// start by generating a random superincreasing sequence
	// TODO make this random and not stupid
	privateKey := []int64{int64(min + 1)}
	sumSoFar := int64(min + 1)
	for len(privateKey) < keyLength {
		privateKey = append(privateKey, sumSoFar+1)
		sumSoFar += sumSoFar + 1
	}

	// the modulus should be greater than sum(privateKey)
	// TODO make this random and not stupid
	m := sumSoFar + 1
	w := randomCoprime(m)
	wi, err := inverse(w, m)
	if err != nil {
		return nil, err
	}

	// calculate public key (for now, doing now index mangling)
	publicKey := make([]int64, len(privateKey))
	for idx, n := range privateKey {
		publicKey[idx] = (n * w) % m
	}

	return &Knapsack{
		PublicKey:  publicKey,
		privateKey: privateKey,
		m:          m,
		w:          w,
		wi:         wi,
	}, nil
}

// Encrypt uses `message` [m0, ..., mn] as an index map on the public
// key [p0, ..., pn] to compute ct = sum(m*p). The PK and output are int64
// as the sums may potentially be quite large. All elements of the message
// are 0 or 1 as it is the bit representation of some string.
func Encrypt(publicKey []int64, message []byte) (int64, error) {
	if len(publicKey) < len(message) {
		return 0, errors.New("public key must be longer than message")
	}
	var ct int64
	for idx, bit := range message {
		ct += publicKey[idx] * int64(bit)
	}
	return ct, nil
}

// Decrypt uses the private information to solve the knapsack problem and returns
// the message as a slice of bits.
func (k *Knapsack) Decrypt(ct int64) []byte {
	// undo the mutation of `w`
	c := (ct * k.wi) % k.m
	// solve the knapsack problem with weights=privateKey, target=c
	msg := solveKnapsack(k.privateKey, c)
	return msg
}

// StringToBits returns a slice of [x0, x1, ..] where xi is 0 or 1.
// the slice itself is the bits of the binary representation of the bytes
// of the string -- not the runes.
func StringToBits(s string) []byte {
	bytesOfStr := []byte(s)
	bitLen := 8 * len(bytesOfStr)
	bitsOfStr := make([]byte, bitLen)
	for i, b := range bytesOfStr {
		bitIdx := 0
		for b > 0 {
			bitsOfStr[(i*8)+bitIdx] = ((b & 0x80) >> 7) & 1 // just the top bit of the byte
			b <<= 1
			bitIdx++
		}
	}
	return bitsOfStr
}

// returns the mask (e.g. [0, 1, 1, 0]) of the weights to choose to reach target
// this function assumes:
//   a) the private key is a superincreasing sequence
//   b) a solution exists (at least for now...may add failure cases later)
func solveKnapsack(weights []int64, s int64) []byte {
	var solve func([]int64, int64, int64)
	solution := make([]byte, len(weights))
	solutionIdx := len(weights) - 1
	solve = func(remainingWeights []int64, sumOfRemainingWeights int64, target int64) {
		if len(remainingWeights) == 0 || target == 0 {
			return
		}
		last := remainingWeights[len(remainingWeights)-1]
		weightsWithoutLast := remainingWeights[:len(remainingWeights)-1]
		sumWithoutLast := sumOfRemainingWeights - last

		if target > sumWithoutLast {
			solution[solutionIdx] = 1
			solutionIdx--
			solve(weightsWithoutLast, sumWithoutLast, target-last)
		} else {
			solution[solutionIdx] = 0
			solutionIdx--
			solve(weightsWithoutLast, sumWithoutLast, target)
		}
	}
	solve(weights, sum(weights), s)
	return solution
}

// reduces the array with summation fn
func sum(arr []int64) int64 {
	var sum int64 = 0
	for _, n := range arr {
		sum += n
	}
	return sum
}

// compute the multiplicate inverse of a mod n
func inverse(a, n int64) (int64, error) {
	var t, newt int64
	var r, newr int64

	t, newt = 0, 1
	r, newr = n, a

	for newr != 0 {
		var quotient int64 = r / newr
		t, newt = newt, t-quotient*newt
		r, newr = newr, r-quotient*newr
	}
	if r > 1 {
		return 0, fmt.Errorf("%d is not invertible mod %d", a, n)
	}
	if t < 0 {
		t = t + n
	}
	return t, nil
}

// compute a mod n without the float64 bs
func mod(a, n int64) int64 {
	if a < 0 {
		a = -a
	}
	if a < n {
		return a
	}
	q := a / n
	return a - (n * q)
}

func gcd(a, b int64) int64 {
	if b == 0 {
		return a
	}
	return gcd(b, a%b)
}

// get a random number m such that gcd(m,n)=1
func randomCoprime(n int64) int64 {
	var r int64
	for r < 2 || gcd(r, n) != 1 {
		r = rand.Int63n(n)
	}
	return r
}
