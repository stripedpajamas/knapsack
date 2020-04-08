package knapsack

import (
	"math"
)

// SolveKnapsack attempts to return a list of weights that exactly fit in a
// knapsack of size s
func SolveKnapsack(weights []int, s int) []int {
	// weights that are superincreasing sequences can be solved trivially
	if isSuperincreasingSequence(weights) {
		return easySolve(weights, s)
	}
	// other forms need brute forcing
	return bruteForce(weights, s)
}

func easySolve(weights []int, s int) []int {
	var solve func([]int, int, []int, int) []int
	solve = func(remainingWeights []int, sumOfRemainingWeights int, solution []int, target int) []int {
		if len(remainingWeights) == 0 || target == 0 {
			if sumInts(solution) == s {
				return solution
			}
			return []int{}
		}
		last := remainingWeights[len(remainingWeights)-1]
		weightsWithoutLast := remainingWeights[:len(remainingWeights)-1]
		sumWithoutLast := sumOfRemainingWeights - last

		if target > sumWithoutLast {
			return solve(weightsWithoutLast, sumWithoutLast, append(solution, last), target-last)
		}
		return solve(weightsWithoutLast, sumWithoutLast, solution, target)
	}
	return solve(weights, sumInts(weights), make([]int, 0), s)
}

func sumInts(arr []int) int {
	sum := 0
	for _, n := range arr {
		sum += n
	}
	return sum
}

func isSuperincreasingSequence(arr []int) bool {
	if len(arr) < 2 {
		return true
	}
	sum := arr[0]

	for i := 1; i < len(arr); i++ {
		if arr[i] <= sum {
			return false
		}
		sum += arr[i]
	}
	return true
}

// returns an array of sets weights that perfectly fit the knapsack, if any
func bruteForce(weights []int, s int) []int {
	mid := len(weights) / 2
	left := weights[:mid]
	right := weights[mid:]

	leftMasks := generateIndexMasks(len(left))
	rightMasks := generateIndexMasks(len(right))

	leftSums := computeUniqueSums(left, leftMasks)
	rightSums := computeUniqueSums(right, rightMasks)

	// solutions := make([][]int, 0)
	for sum, leftMask := range leftSums {
		if rightMask, present := rightSums[s-sum]; present {
			return constructSolution(weights, leftMask, rightMask)
			// solutions = append(solutions, constructSolution(weights, leftMask, rightMask))
		}
	}

	return []int{}

	// return solutions
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
