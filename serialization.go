package knapsack

import (
	"math/big"

	"github.com/vmihailenco/msgpack"
)

// PublicKeyFile contains only the public key and is suitable for sharing
type PublicKeyFile struct {
	PubKey [][]byte
}

// PrivateKeyFile contains only the private constants used to decrypt messages
type PrivateKeyFile struct {
	PrivKey [][]byte
	M       []byte // modulus
	W       []byte // random mutating constant
	WI      []byte // inverse of w
}

// KeyFile allows getting the key out of a public or private file
type KeyFile interface {
	GetKey() [][]byte
}

// GetKey returns the public key
func (p PublicKeyFile) GetKey() [][]byte {
	return p.PubKey
}

// GetKey returns the private key
func (p PrivateKeyFile) GetKey() [][]byte {
	return p.PrivKey
}

// Pack serializes a knapsack and returns the packed bytes (PubKeyFile, PrivKeyFile, error)
func Pack(k Knapsack) ([]byte, []byte, error) {
	pub, err := msgpack.Marshal(&PublicKeyFile{
		PubKey: prepareSliceOfBigs(k.PublicKey),
	})
	if err != nil {
		return nil, nil, err
	}
	priv, err := msgpack.Marshal(&PrivateKeyFile{
		PrivKey: prepareSliceOfBigs(k.PrivateKey),
		M:       k.M.Bytes(),
		W:       k.W.Bytes(),
		WI:      k.WI.Bytes(),
	})
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

// Unpack deserializes a public and private key file into a Knapsack struct
func Unpack(pubKeyFile *PublicKeyFile, privKeyFile *PrivateKeyFile) *Knapsack {
	k := UnpackPrivate(privKeyFile)
	k.PublicKey = unpackKey(pubKeyFile)
	return k
}

// UnpackPublic returns the public key from the serialized public key file
func UnpackPublic(pubKeyFile *PublicKeyFile) []*big.Int {
	return unpackKey(pubKeyFile)
}

// UnpackPrivate returns a Knapsack by deserializing the private key params
func UnpackPrivate(privKeyFile *PrivateKeyFile) *Knapsack {
	privateKey := unpackKey(privKeyFile)
	return &Knapsack{
		PublicKey:  nil,
		PrivateKey: privateKey,
		M:          unpackBigInt(privKeyFile.M),
		W:          unpackBigInt(privKeyFile.W),
		WI:         unpackBigInt(privKeyFile.WI),
	}
}

func unpackKey(keyFile KeyFile) []*big.Int {
	key := keyFile.GetKey()
	out := make([]*big.Int, len(key))
	for i, bs := range key {
		out[i] = unpackBigInt(bs)
	}
	return out
}

func unpackBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func prepareSliceOfBigs(arr []*big.Int) [][]byte {
	out := make([][]byte, len(arr))

	for i, b := range arr {
		out[i] = b.Bytes()
	}

	return out
}
