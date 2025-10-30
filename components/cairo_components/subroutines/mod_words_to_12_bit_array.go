package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type ModWordsTo12BitArrayResult struct {
	Sum            m31.QM31
	RangeCheckSums [5]m31.QM31
	Outputs        [16]m31.QM31
}

func ModWordsTo12BitArrayEvaluate(
	qm31 *m31.QM31Chip,
	input []m31.QM31,
	limb1b0 m31.QM31,
	limb2b0 m31.QM31,
	limb5b0 m31.QM31,
	limb6b0 m31.QM31,
	limb9b0 m31.QM31,
	limb1b1 m31.QM31,
	limb2b1 m31.QM31,
	limb5b1 m31.QM31,
	limb6b1 m31.QM31,
	limb9b1 m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) ModWordsTo12BitArrayResult {
	if len(input) != 22 {
		panic("ModWordsTo12BitArrayEvaluate expects 22 input limbs")
	}

	const (
		scale8   = 8
		scale64  = 64
		scale512 = 512
	)

	limb0 := input[0]
	limb1 := input[1]
	limb2 := input[2]
	limb3 := input[3]
	limb4 := input[4]
	limb5 := input[5]
	limb6 := input[6]
	limb7 := input[7]
	limb8 := input[8]
	limb9 := input[9]
	limb10 := input[10]

	limb28 := input[11]
	limb29 := input[12]
	limb30 := input[13]
	limb31 := input[14]
	limb32 := input[15]
	limb33 := input[16]
	limb34 := input[17]
	limb35 := input[18]
	limb36 := input[19]
	limb37 := input[20]
	limb38 := input[21]

	qm8 := qm31Const(scale8)
	qm64 := qm31Const(scale64)
	qm512 := qm31Const(scale512)

	limb1a0 := qm31.Sub(limb1, qm31.Mul(limb1b0, qm8))
	limb2a0 := qm31.Sub(limb2, qm31.Mul(limb2b0, qm64))

	sum0, err := qm31.Combine(rangeCheckElements, []m31.QM31{limb1a0, limb1b0, limb2a0, limb2b0})
	if err != nil {
		panic(err)
	}

	limb5a0 := qm31.Sub(limb5, qm31.Mul(limb5b0, qm8))
	limb6a0 := qm31.Sub(limb6, qm31.Mul(limb6b0, qm64))

	sum1, err := qm31.Combine(rangeCheckElements, []m31.QM31{limb5a0, limb5b0, limb6a0, limb6b0})
	if err != nil {
		panic(err)
	}

	limb9a0 := qm31.Sub(limb9, qm31.Mul(limb9b0, qm8))
	limb1a1 := qm31.Sub(limb29, qm31.Mul(limb1b1, qm8))
	limb2a1 := qm31.Sub(limb30, qm31.Mul(limb2b1, qm64))

	sum2, err := qm31.Combine(rangeCheckElements, []m31.QM31{limb1a1, limb1b1, limb2a1, limb2b1})
	if err != nil {
		panic(err)
	}

	limb5a1 := qm31.Sub(limb33, qm31.Mul(limb5b1, qm8))
	limb6a1 := qm31.Sub(limb34, qm31.Mul(limb6b1, qm64))

	sum3, err := qm31.Combine(rangeCheckElements, []m31.QM31{limb5a1, limb5b1, limb6a1, limb6b1})
	if err != nil {
		panic(err)
	}

	limb9a1 := qm31.Sub(limb37, qm31.Mul(limb9b1, qm8))

	sum4, err := qm31.Combine(rangeCheckElements, []m31.QM31{limb9a0, limb9b0, limb9b1, limb9a1})
	if err != nil {
		panic(err)
	}

	outputs := [16]m31.QM31{
		qm31.Add(limb0, qm31.Mul(qm512, limb1a0)),
		qm31.Add(limb1b0, qm31.Mul(qm64, limb2a0)),
		qm31.Add(limb2b0, qm31.Mul(qm8, limb3)),
		qm31.Add(limb4, qm31.Mul(qm512, limb5a0)),
		qm31.Add(limb5b0, qm31.Mul(qm64, limb6a0)),
		qm31.Add(limb6b0, qm31.Mul(qm8, limb7)),
		qm31.Add(limb8, qm31.Mul(qm512, limb9a0)),
		qm31.Add(limb9b0, qm31.Mul(qm64, limb10)),
		qm31.Add(limb28, qm31.Mul(qm512, limb1a1)),
		qm31.Add(limb1b1, qm31.Mul(qm64, limb2a1)),
		qm31.Add(limb2b1, qm31.Mul(qm8, limb31)),
		qm31.Add(limb32, qm31.Mul(qm512, limb5a1)),
		qm31.Add(limb5b1, qm31.Mul(qm64, limb6a1)),
		qm31.Add(limb6b1, qm31.Mul(qm8, limb35)),
		qm31.Add(limb36, qm31.Mul(qm512, limb9a1)),
		qm31.Add(limb9b1, qm31.Mul(qm64, limb38)),
	}

	return ModWordsTo12BitArrayResult{
		Sum: sum,
		RangeCheckSums: [5]m31.QM31{
			sum0,
			sum1,
			sum2,
			sum3,
			sum4,
		},
		Outputs: outputs,
	}
}
