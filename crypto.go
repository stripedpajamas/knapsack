package knapsack

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Knapsack contains the private data used to generate the public key and decrypt messages
type Knapsack struct {
	PublicKey  []*big.Int
	PrivateKey []*big.Int
	M          *big.Int // modulus
	W          *big.Int // random mutating constant
	WI         *big.Int // inverse of w
}

// NewKnapsack auto generates private knapsack params
func NewKnapsack(keyLength int64) (*Knapsack, error) {
	if keyLength < 1 {
		return nil, errors.New("key length must be > 0")
	}
	// start by generating a random superincreasing sequence
	one := big.NewInt(1)
	privateKey, err := randomSuperincreasingSequence(keyLength)
	if err != nil {
		return nil, err
	}

	// the modulus should be in [ 2^(length * 2 + 1) + 1, 2^(length * 2 + 2) - 1 ]
	min := new(big.Int).Exp(big.NewInt(2), big.NewInt(keyLength*2+1), nil) // 2^(length * 2 + 1)
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(keyLength*2+2), nil) // 2^(length * 2 + 2)
	min.Add(min, one)                                                      // 2^(length * 2 + 1) + 1
	max.Sub(max, one)                                                      // 2^(length * 2 + 2) - 1
	m, err := randomUniform(min, max)
	if err != nil {
		return nil, err
	}

	// w' should be in [ 2, m - 2 ]
	min.SetInt64(2)
	max = new(big.Int).Sub(m, min)

	// goal of this loop: get a good `w` that has an inverse mod m
	var w, wi *big.Int
	for w == nil || wi == nil {
		wPrime, err := randomUniform(min, max)
		if err != nil {
			return nil, err
		}

		// w = wPrime/gcd(wPrime, m); wi = inverse of w
		w = new(big.Int).Div(wPrime, new(big.Int).GCD(nil, nil, wPrime, m))
		wi = new(big.Int).ModInverse(w, m)
	}

	// calculate public key (for now, not doing index mangling)
	publicKey := make([]*big.Int, len(privateKey))
	for idx, n := range privateKey {
		nw := new(big.Int).Mul(n, w)
		publicKey[idx] = nw.Mod(nw, m)
	}

	return &Knapsack{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		M:          m,
		W:          w,
		WI:         wi,
	}, nil
}

// GetKeyId returns first 10 bytes of sha256(key)
func GetKeyId(key []*big.Int) []byte {
	h := sha256.New()
	for _, n := range key {
		h.Write(n.Bytes())
	}
	return h.Sum(nil)[:10]
}

// EncryptString encrypts `message` using `publicKey`.
func EncryptString(publicKey []*big.Int, message string) ([]byte, error) {
	return EncryptBytes(publicKey, []byte(message))
}

// EncryptBytes encrypts `messageBytes` using `publicKey`.
func EncryptBytes(publicKey []*big.Int, messageBytes []byte) ([]byte, error) {
	ct, err := encrypt(publicKey, bytesToBits(messageBytes))
	if err != nil {
		return nil, err
	}
	return ct.Bytes(), nil
}

func encrypt(publicKey []*big.Int, messageBits []byte) (*big.Int, error) {
	if len(publicKey) < len(messageBits) {
		return nil, errors.New("public key must be longer than messageBits")
	}
	ct := big.NewInt(0)
	for idx, bit := range messageBits {
		if bit == 1 {
			ct.Add(ct, publicKey[idx])
		}
	}
	return ct, nil
}

// Decrypt uses the private key to solve the knapsack problem and returns
// the message reconstructed into bytes from the slice of bits.
func (k *Knapsack) Decrypt(ct *big.Int) []byte {
	// undo the mutation of `w`
	c := new(big.Int).Mul(ct, k.WI)
	c.Mod(c, k.M)
	// solve the knapsack problem with weights=privateKey, target=c
	msg := solveKnapsack(k.PrivateKey, c)
	return bitsToBytes(msg)
}

// DecryptBytes constructs the ciphertext int from the bytes
// and uses the private key to solve the knapsack problem.
// The message is reconstructed into bytes from the slice of bits.
func (k *Knapsack) DecryptBytes(ct []byte) []byte {
	return k.Decrypt(new(big.Int).SetBytes(ct))
}

// returns a slice of [x0, x1, ..] where xi is 0 or 1.
// the slice itself is the bits of the binary representation of the bytes
// of the string -- not the runes.
func stringToBits(s string) []byte {
	return bytesToBits([]byte(s))
}

func bytesToBits(bs []byte) []byte {
	bitLen := 8 * len(bs)
	bitsOfBytes := make([]byte, bitLen)
	for i, b := range bs {
		bitIdx := 0
		for b > 0 {
			bitsOfBytes[(i*8)+bitIdx] = ((b & 0x80) >> 7) & 1 // just the top bit of the byte
			b <<= 1
			bitIdx++
		}
	}
	return bitsOfBytes
}

func bitsToBytes(bs []byte) []byte {
	byteLen := len(bs) / 8
	bytesOfBits := make([]byte, byteLen)

	var currentByte byte
	for i, b := range bs {
		currentByte |= b
		if i%8 == 7 {
			bytesOfBits[i/8] = currentByte
			currentByte = 0
		} else {
			currentByte <<= 1
		}
	}
	return bytesOfBits
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

func randomUniform(min, max *big.Int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Sub(max, min))
	if err != nil {
		return nil, err
	}
	return n.Add(n, min), nil
}

func randomSuperincreasingSequence(length int64) ([]*big.Int, error) {
	// choose random numbers in the range:
	// [ (2^(i-1) - 1) * 2^length + 1, 2^(i-1) * 2^length ]
	// the above assumes 1-indexed arrays; our arrays are 0-indexed,
	// so s/i-1/i/. rand.Int is exclusive, so we need add 1 to the max:
	// [ (2^i - 1) * 2^length + 1, 2^i * 2^length + 1 ]
	one := big.NewInt(1)
	twoLen := new(big.Int).Exp(big.NewInt(2), big.NewInt(length), nil) // 2^length
	multiplier := new(big.Int).Add(twoLen, one)                        // 2^length + 1

	out := make([]*big.Int, length)
	for i := range out {
		max := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), nil) // 2^i
		min := new(big.Int).Sub(max, one)                                 // 2^i - 1
		min.Mul(min, multiplier)                                          // 2^i - 1 * 2^length
		max.Mul(max, multiplier)                                          // 2^i * 2^length

		n, err := randomUniform(min, max)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}

	return out, nil
}
