package crypto

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Knapsack contains the private data used to generate the public key and decrypt messages
type Knapsack struct {
	PublicKey  []*big.Int
	privateKey []*big.Int
	m          *big.Int // modulus
	w          *big.Int // random mutating constant
	wi         *big.Int // inverse of w
}

// NewKnapsack auto generates private knapsack params
func NewKnapsack(keyLength int64) (*Knapsack, error) {
	// private sequence should begin at around 2^n (n is the sequence length)
	// and should end around 2^2n
	min := new(big.Int).Exp(big.NewInt(2), big.NewInt(keyLength), nil)
	// max := math.Pow(2, float64(2*keyLength))

	// start by generating a random superincreasing sequence
	// TODO make this random and not stupid
	one := big.NewInt(1)
	privateKey := []*big.Int{new(big.Int).Add(min, one)}
	sumSoFar := new(big.Int).Add(min, one)
	for len(privateKey) < int(keyLength) {
		privateKey = append(privateKey, new(big.Int).Add(sumSoFar, one))
		sumSoFar.Add(sumSoFar, new(big.Int).Add(sumSoFar, one))
	}

	// the modulus should be greater than sum(privateKey)
	// TODO make this random and not stupid
	m := new(big.Int).Add(sumSoFar, one)
	w, err := randomCoprime(m)
	if err != nil {
		return nil, err
	}
	wi := new(big.Int).ModInverse(w, m)

	// calculate public key (for now, doing now index mangling)
	publicKey := make([]*big.Int, len(privateKey))
	for idx, n := range privateKey {
		nw := new(big.Int).Mul(n, w)
		publicKey[idx] = nw.Mod(nw, m)
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
// key [p0, ..., pn] to compute ct = sum(m*p). All elements of the message
// are 0 or 1 as it is the bit representation of some string.
func Encrypt(publicKey []*big.Int, message []byte) (*big.Int, error) {
	if len(publicKey) < len(message) {
		return nil, errors.New("public key must be longer than message")
	}
	ct := big.NewInt(0)
	for idx, bit := range message {
		if bit == 1 {
			ct.Add(ct, publicKey[idx])
		}
	}
	return ct, nil
}

// Decrypt uses the private information to solve the knapsack problem and returns
// the message as a slice of bits.
func (k *Knapsack) Decrypt(ct *big.Int) []byte {
	// undo the mutation of `w`
	c := new(big.Int).Mul(ct, k.wi)
	c.Mod(c, k.m)
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
func solveKnapsack(weights []*big.Int, s *big.Int) []byte {
	zero := big.NewInt(0)
	solution := make([]byte, len(weights))
	solutionIdx := len(weights) - 1

	var solve func([]*big.Int, *big.Int, *big.Int)
	solve = func(remainingWeights []*big.Int, sumOfRemainingWeights *big.Int, target *big.Int) {
		if len(remainingWeights) == 0 || target.Cmp(zero) == 0 {
			return
		}
		last := remainingWeights[len(remainingWeights)-1]
		weightsWithoutLast := remainingWeights[:len(remainingWeights)-1]
		sumWithoutLast := new(big.Int).Sub(sumOfRemainingWeights, last)

		if target.Cmp(sumWithoutLast) > 0 {
			solution[solutionIdx] = 1
			solutionIdx--
			solve(weightsWithoutLast, sumWithoutLast, target.Sub(target, last))
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
func sum(arr []*big.Int) *big.Int {
	sum := new(big.Int)
	for _, n := range arr {
		sum.Add(sum, n)
	}
	return sum
}

// get a random number m such that gcd(m,n)=1
func randomCoprime(n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	gcd := new(big.Int)
	r := new(big.Int)
	var err error
	for r.Cmp(two) < 0 || gcd.Cmp(one) != 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		gcd.GCD(nil, nil, r, n)
	}
	return r, nil
}
