package main

import (
	"fmt"

	"github.com/stripedpajamas/knapsack"
)

type example struct {
	weights []int
	s       int
}

func main() {
	examples := []example{
		{weights: []int{1, 2, 3, 4, 5}, s: 10},
		{weights: []int{5, 10, 17, 33, 70}, s: 32},
	}

	for _, example := range examples {
		solution := knapsack.SolveKnapsack(example.weights, example.s)
		fmt.Printf("for weights %v and knapsack size %d:\n\t%v\n", example.weights, example.s, solution)
	}
}
