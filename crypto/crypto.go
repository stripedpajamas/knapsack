package crypto

import "errors"

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
