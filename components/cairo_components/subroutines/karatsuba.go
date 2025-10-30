package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type SingleKaratsubaN8Result struct {
	Sum    m31.QM31
	Output [31]m31.QM31
}

func SingleKaratsubaN8Evaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) SingleKaratsubaN8Result {
	if len(input) != 32 {
		panic("SingleKaratsubaN8Evaluate expects 32 limbs")
	}

	outputSlice := karatsubaCombine(
		qm31,
		input[:8],
		input[8:16],
		input[16:24],
		input[24:32],
	)

	var output [31]m31.QM31
	copy(output[:], outputSlice)

	return SingleKaratsubaN8Result{
		Sum:    sum,
		Output: output,
	}
}

type SingleKaratsubaN7Result struct {
	Sum    m31.QM31
	Output [27]m31.QM31
}

func SingleKaratsubaN7Evaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) SingleKaratsubaN7Result {
	if len(input) != 28 {
		panic("SingleKaratsubaN7Evaluate expects 28 limbs")
	}

	outputSlice := karatsubaCombine(
		qm31,
		input[:7],
		input[7:14],
		input[14:21],
		input[21:28],
	)

	var output [27]m31.QM31
	copy(output[:], outputSlice)

	return SingleKaratsubaN7Result{
		Sum:    sum,
		Output: output,
	}
}

type DoubleKaratsubaN8LimbMaxBound4095Result struct {
	Sum    m31.QM31
	Output [63]m31.QM31
}

func DoubleKaratsubaN8LimbMaxBound4095Evaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) DoubleKaratsubaN8LimbMaxBound4095Result {
	if len(input) != 64 {
		panic("DoubleKaratsubaN8LimbMaxBound4095Evaluate expects 64 limbs")
	}

	outputSlice := karatsubaCombine(
		qm31,
		input[:16],
		input[16:32],
		input[32:48],
		input[48:64],
	)

	var output [63]m31.QM31
	copy(output[:], outputSlice)

	return DoubleKaratsubaN8LimbMaxBound4095Result{
		Sum:    sum,
		Output: output,
	}
}

type DoubleKaratsubaN7LimbMaxBound511Result struct {
	Sum    m31.QM31
	Output [55]m31.QM31
}

func DoubleKaratsubaN7LimbMaxBound511Evaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	sum m31.QM31,
	_ m31.QM31,
	_ m31.QM31,
) DoubleKaratsubaN7LimbMaxBound511Result {
	if len(input) != 56 {
		panic("DoubleKaratsubaN7LimbMaxBound511Evaluate expects 56 limbs")
	}

	outputSlice := karatsubaCombine(
		qm31,
		input[:14],
		input[14:28],
		input[28:42],
		input[42:56],
	)

	var output [55]m31.QM31
	copy(output[:], outputSlice)

	return DoubleKaratsubaN7LimbMaxBound511Result{
		Sum:    sum,
		Output: output,
	}
}

func karatsubaCombine(
	qm31 *m31.QM31Chip,
	aLow, aHigh, bLow, bHigh []m31.QM31,
) []m31.QM31 {
	halfLen := len(aLow)
	if len(aHigh) != halfLen || len(bLow) != halfLen || len(bHigh) != halfLen {
		panic("karatsubaCombine expects equal limb lengths")
	}

	z0 := convolveLimbs(qm31, aLow, bLow)
	z2 := convolveLimbs(qm31, aHigh, bHigh)

	xSum := addVectors(qm31, aLow, aHigh)
	ySum := addVectors(qm31, bLow, bHigh)
	z1 := convolveLimbs(qm31, xSum, ySum)

	middle := make([]m31.QM31, len(z1))
	for i := range middle {
		val := qm31.Sub(z1[i], z0[i])
		val = qm31.Sub(val, z2[i])
		middle[i] = val
	}

	result := make([]m31.QM31, 4*halfLen-1)
	for i := range result {
		result[i] = qm31.Zero()
	}
	copy(result, z0)

	for i := range middle {
		idx := i + halfLen
		result[idx] = qm31.Add(result[idx], middle[i])
	}

	for i := range z2 {
		idx := i + 2*halfLen
		result[idx] = qm31.Add(result[idx], z2[i])
	}

	return result
}

func addVectors(qm31 *m31.QM31Chip, a, b []m31.QM31) []m31.QM31 {
	if len(a) != len(b) {
		panic("addVectors expects slices of equal length")
	}
	result := make([]m31.QM31, len(a))
	for i := range result {
		result[i] = qm31.Add(a[i], b[i])
	}
	return result
}
