package main

import (
	"fmt"
	"math"
)

func main() {
	weights := []int{1, 2, 3, 4, 5}
	s := 10

	// print a/all solution/s to general knapsack problem
	solutions := compute(weights, s)
	fmt.Printf("for weights %v and knapsack size %d:\n\t%v\n", weights, s, solutions)
}

// returns an array of sets weights that perfectly fit the knapsack, if any
func compute(weights []int, s int) [][]int {
	mid := len(weights) / 2
	left := weights[:mid]
	right := weights[mid:]

	leftMasks := generateIndexMasks(len(left))
	rightMasks := generateIndexMasks(len(right))

	leftSums := computeUniqueSums(left, leftMasks)
	rightSums := computeUniqueSums(right, rightMasks)

	solutions := make([][]int, 0)
	for sum, leftMask := range leftSums {
		if rightMask, present := rightSums[s-sum]; present {
			solutions = append(solutions, constructSolution(weights, leftMask, rightMask))
		}
	}

	return solutions
}

func constructSolution(weights, leftMask, rightMask []int) []int {
	out := make([]int, 0)
	for i, m := range leftMask {
		weight := weights[i] * m
		if weight > 0 {
			out = append(out, weight)
		}
	}
	for i, m := range rightMask {
		weight := weights[len(leftMask)+i] * m
		if weight > 0 {
			out = append(out, weight)
		}
	}
	return out
}

func computeUniqueSums(arr []int, masks [][]int) map[int][]int {
	sums := make(map[int][]int)
	for _, mask := range masks {
		sums[sumWithMask(arr, mask)] = mask
	}
	return sums
}

func sumWithMask(arr []int, mask []int) int {
	if len(arr) != len(mask) {
		panic("input array and mask must have equal lengths")
	}

	sum := 0
	for i := range arr {
		sum += arr[i] * mask[i]
	}

	return sum
}

func generateIndexMasks(length int) [][]int {
	// make an array of length 2^len(arr)
	masks := make([][]int, int(math.Pow(2, float64(length))))

	// fill it with binary representation of indexes
	for i := 0; i < len(masks); i++ {
		masks[i] = make([]int, length)
		n := i
		j := len(masks[i]) - 1
		for n > 0 {
			if j < 0 {
				break
			}
			masks[i][j] = int(n & 1)
			n >>= 1
			j--
		}
	}

	return masks
}
