# knapsack

a really basic tool to play with the Merkle-Hellman knapsack cryptosystem

**it's a toy; don't use for anything that's actually sensitive.**

## install
you have to have Go installed first: [Go install instructions here](https://golang.org/doc/install)

to install the knapsack cli:
```shell
go get github.com/stripedpajamas/knapsack/cmd/...
```

## use
generate public/private key files:
```shell
knapsack new [length <int>]
```

the default key length is 100; keep in mind that you can only encrypt data with a bit length < key length.

the key files are msgpack-encoded and aren't intended to be human-readable.

the public file (`knapsack_public.pack`) is used by other people to encrypt things that only you can read (with `knapsack_private.pack`).

encryption outputs hex, decryption expects hex as input.

```shell
$ knapsack --help
Usage: knapsack <command>

Flags:
  --help    Show context-sensitive help.

Commands:
  new
    Create a new Knapsack

  encrypt --pubfile=STRING
    Encrypt stdin (default), text, or files using a public key

  decrypt --privfile=STRING
    Decrypt stdin (default), text, or files using a private key

Run "knapsack <command> --help" for more information on a command.
```

### examples
**basic encrypt/decrypt text**
```shell
$ knapsack encrypt -p knapsack_public.pack -t "hello world"
Encrypting using public key 3a0cbf6b2084861283e6...

3de52342b3ba3ad163b2db16655efdade6fde443bf21e561aa4f
$ knapsack decrypt -p knapsack_private.pack -t 3de52342b3ba3ad163b2db16655efdade6fde443bf21e561aa4f
Decrypting using private key 8552ed80921d8d2f6de1...

hello world
$
```

**reading from stdin**
```shell
$ echo "hello world" | knapsack encrypt -p knapsack_public.pack
Encrypting using public key 3a0cbf6b2084861283e6...

Reading input from stdin...

4260a558dc7fd858717a7dbf8666e2f0b82c3a9cf1407e7032bf
$ knapsack encrypt -p knapsack_public.pack -t "hello world" | knapsack decrypt -p knapsack_private.pack
Encrypting using public key 3a0cbf6b2084861283e6...

Decrypting using private key 8552ed80921d8d2f6de1...

Reading input from stdin...

hello world
$
```

**files**

input and output for encrypt or decrypt can be passed with `-i` and `-o`
```shell
$ knapsack encrypt -p knapsack_public.pack -i input.txt -o input.enc
Encrypting using public key ddd453fba5657aec4578...

Successfully encrypted and saved to input.enc
$ cat input.enc
5ed61faefd9dcc6c8ef589c00b43cdf62253914758033a1cd3918bb9db3cf7579f616e4568ae0867835506d4e996e28e87db46
$ knapsack decrypt -p knapsack_private.pack -i input.enc -o input.dec
Decrypting using private key e3a5235b87323944b011...

Successfully decrypted and saved to input.dec
$ cat input.dec
hello world from a file
$
```



## more info
for more understanding what a knapsack is and how it can be used in cryptographic settings (and how some schemes are broken):
- [The Rise and Fall of Knapsack Cryptosystems](http://www.dtc.umn.edu/~odlyzko/doc/arch/knapsack.survey.pdf)
- [On breaking the iterated Merkle-Hellman public-key cryptosystem](https://doi.org/10.1007%2F978-1-4757-0602-4_29)
- [Hiding Information and Signatures in Trapdoor Knapsacks](https://ee.stanford.edu/~hellman/publications/30.pdf)
- [A Polynomial Time Algorithm for Breaking the Basic Merkle-Hellman Cryptosystem](https://link.springer.com/chapter/10.1007/978-1-4757-0602-4_27)

(_scihub is your friend_)


## license
MIT
