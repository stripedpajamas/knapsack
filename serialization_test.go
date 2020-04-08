package knapsack

import (
	"testing"

	"github.com/vmihailenco/msgpack"
)

func TestPackUnpack(t *testing.T) {
	k, err := NewKnapsack(100)
	handleFatalError(err, t)

	pubKeyFile, privKeyFile, err := Pack(*k)
	handleFatalError(err, t)

	t.Logf("pub file:\n\t%v\npriv file:\n\t%v\n", pubKeyFile, privKeyFile)

	a := PublicKeyFile{}
	b := PrivateKeyFile{}
	err = msgpack.Unmarshal(pubKeyFile, &a)
	handleFatalError(err, t)
	err = msgpack.Unmarshal(privKeyFile, &b)
	handleFatalError(err, t)

	kUnpacked := Unpack(&a, &b)

	if equal, msg := equalKnapsacks(k, kUnpacked); !equal {
		t.Error(msg)
	}
}

func handleFatalError(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func equalKnapsacks(ka, kb *Knapsack) (bool, string) {
	for i, n := range ka.PublicKey {
		if kb.PublicKey[i].Cmp(n) != 0 {
			return false, "public keys unequal"
		}
	}
	for i, n := range ka.PrivateKey {
		if kb.PrivateKey[i].Cmp(n) != 0 {
			return false, "private keys unequal"
		}
	}
	if kb.M.Cmp(ka.M) != 0 {
		return false, "M unequal"
	}
	if kb.W.Cmp(ka.W) != 0 {
		return false, "W unequal"
	}
	if kb.WI.Cmp(ka.WI) != 0 {
		return false, "WI unequal"
	}
	return true, ""
}
