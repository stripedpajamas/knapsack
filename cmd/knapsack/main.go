package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/stripedpajamas/knapsack"
	"github.com/vmihailenco/msgpack"
)

type NewCmd struct {
	Length int64  `default:"100" help:"Desired public/private key length."`
	OutDir string `type:"existingdir" name:"out-dir" help:"Output directory for public/private key files"`
}

func (n *NewCmd) Run() error {
	fmt.Fprintf(os.Stderr, "Generating new Knapsack with key length %d...\n\n", n.Length)
	k, err := knapsack.NewKnapsack(n.Length)
	if err != nil {
		return err
	}
	pkf, skf, err := knapsack.Pack(*k)
	if err != nil {
		return err
	}

	pkPath := filepath.Join(n.OutDir, "knapsack_public.pack")
	skPath := filepath.Join(n.OutDir, "knapsack_private.pack")
	err = ioutil.WriteFile(pkPath, pkf, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(skPath, skf, 0600)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Successfully generated Knapsack public key and saved to %s\n", pkPath)
	fmt.Fprintf(os.Stderr, "Successfully generated Knapsack private key and saved to %s\n", skPath)

	return nil
}

type InputCmd interface {
	getText() string
	getInFile() string
}

type EncryptCmd struct {
	PublicKeyFile string `required type:"existingfile" name:"pubfile" short:"p" help:"Path of public key file to use for encryption."`
	Text          string `xor:"input" name:"text" short:"t" help:"Text to encrypt."`
	InFile        string `type:"existingfile" xor:"input" name:"in" short:"i" help:"Input file to encrypt."`
	OutFile       string `type:"path" name:"out" short:"o" help:"Output file to write ciphertext."`
}

func (e EncryptCmd) getText() string {
	return e.Text
}

func (e EncryptCmd) getInFile() string {
	return e.InFile
}

func (e *EncryptCmd) Run() error {
	// load public key
	pkfRaw, err := ioutil.ReadFile(e.PublicKeyFile)
	if err != nil {
		return err
	}
	pkf := &knapsack.PublicKeyFile{}
	err = msgpack.Unmarshal(pkfRaw, pkf)
	if err != nil {
		return err
	}
	pk := knapsack.UnpackPublic(pkf)
	fmt.Fprintf(os.Stderr, "Encrypting using public key %0x...\n\n", knapsack.GetKeyId(pk))

	input, err := getInputBytes(e)
	if err != nil {
		return err
	}
	ct, err := knapsack.EncryptBytes(pk, input)
	if err != nil {
		return err
	}

	if e.OutFile != "" {
		err = ioutil.WriteFile(e.OutFile, []byte(fmt.Sprintf("%0x", ct)), 0600)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Successfully encrypted and saved to %s\n", e.OutFile)
	} else {
		fmt.Printf("%0x\n", ct)
	}
	return nil
}

type DecryptCmd struct {
	PrivateKeyFile string `required type:"existingfile" name:"privfile" short:"p" help:"Path of private key file to use for decryption."`
	Text           string `xor:"input" name:"text" short:"t" help:"Hex-encoded input to decrypt."`
	InFile         string `type:"existingfile" xor:"input" name:"in" short:"i" help:"Input file to decrypt."`
	OutFile        string `type:"path" name:"out" short:"o" help:"Output file to write plaintext."`
}

func (d DecryptCmd) getText() string {
	return d.Text
}

func (d DecryptCmd) getInFile() string {
	return d.InFile
}

func (d *DecryptCmd) Run() error {
	// load knapsack
	skfRaw, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	skf := &knapsack.PrivateKeyFile{}
	err = msgpack.Unmarshal(skfRaw, skf)
	if err != nil {
		return err
	}
	k := knapsack.UnpackPrivate(skf)
	fmt.Fprintf(os.Stderr, "Decrypting using private key %0x...\n\n", knapsack.GetKeyId(k.PrivateKey))

	rawInput, err := getInputBytes(d)
	if err != nil {
		return err
	}

	// input to decrypt is always hex encoded
	input := make([]byte, len(rawInput)/2)
	_, err = hex.Decode(input, bytes.TrimSpace(rawInput))
	if err != nil {
		return err
	}
	plaintext := k.DecryptBytes(input)

	if d.OutFile != "" {
		err = ioutil.WriteFile(d.OutFile, plaintext, 0600)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Successfully decrypted and saved to %s\n", d.OutFile)
	} else {
		fmt.Printf("%s\n", plaintext)
	}
	return nil
}

var cli struct {
	New     NewCmd     `cmd help:"Create a new Knapsack"`
	Encrypt EncryptCmd `cmd help:"Encrypt stdin (default), text, or files using a public key"`
	Decrypt DecryptCmd `cmd help:"Decrypt stdin (default), text, or files using a private key"`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("knapsack"))
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func getInputBytes(cmd InputCmd) ([]byte, error) {
	if cmd.getText() != "" {
		return []byte(cmd.getText()), nil
	}
	if cmd.getInFile() != "" {
		return ioutil.ReadFile(cmd.getInFile())
	}
	// default to stdin
	fmt.Fprintf(os.Stderr, "Reading input from stdin...\n\n")
	return ioutil.ReadAll(os.Stdin)
}
