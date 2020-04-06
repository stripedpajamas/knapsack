## knapsack

was reading [The Rise and Fall of Knapsack Cryptosystems](http://www.dtc.umn.edu/~odlyzko/doc/arch/knapsack.survey.pdf) and wanted to implement the knapsack solution finder it describes. that code is in `solving.go` and `cmd/main.go` uses it to run through some examples.

the paper says to sort the sets before looking for common elements, but I didn't ¯\\_(ツ)\_/¯

```shell
git clone https://github.com/stripedpajamas/knapsack.git
cd knapsack
go run cmd/main.go # for solve examples
```

also messing around with the described cryptosystems in crypto/

## license
MIT
