package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type VerifyMul252Result struct {
	Sum            m31.QM31
	RangeCheckSums [28]m31.QM31
}

func VerifyMul252Evaluate(
	qm31 *m31.QM31Chip,
	aLimbs []m31.QM31,
	bLimbs []m31.QM31,
	cLimbs []m31.QM31,
	k m31.QM31,
	carries []m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) VerifyMul252Result {
	if len(aLimbs) != 28 || len(bLimbs) != 28 || len(cLimbs) != 28 || len(carries) != 27 {
		panic("VerifyMul252Evaluate expects 28-limb operands and 27 carries")
	}

	conv := convolveLimbs(qm31, aLimbs, bLimbs) // length 55

	diff := make([]m31.QM31, len(conv))
	for i := range conv {
		val := conv[i]
		if i < len(cLimbs) {
			val = qm31.Sub(val, cLimbs[i])
		}
		diff[i] = val
	}

	convMod := applyConvModReduction(qm31, diff)

	const (
		offsetK     = 262144
		offsetCarry = 131072
		scaleCarry  = 512
		scaleK136   = 136
		scaleK256   = 256
	)

	kRange := qm31.Add(k, qm31Const(offsetK))
	RangeCheckSums := [28]m31.QM31{}
	var err error
	RangeCheckSums[0], err = qm31.Combine(rangeCheckElements, []m31.QM31{kRange})
	if err != nil {
		panic(err)
	}

	constScaleCarry := qm31Const(scaleCarry)
	constScale136 := qm31Const(scaleK136)
	constScale256 := qm31Const(scaleK256)

	for i := 0; i < len(carries); i++ {
		val := qm31.Add(carries[i], qm31Const(offsetCarry))
		RangeCheckSums[i+1], err = qm31.Combine(rangeCheckElements, []m31.QM31{val})
		if err != nil {
			panic(err)
		}
	}

	// carry_0 constraint
	constraint := qm31.Sub(
		qm31.Mul(carries[0], constScaleCarry),
		qm31.Sub(convMod[0], k),
	)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	for i := 1; i < len(carries); i++ {
		right := qm31.Add(convMod[i], carries[i-1])
		if i == 21 { // special subtraction with 136 * k
			right = qm31.Sub(right, qm31.Mul(constScale136, k))
		}
		constraint = qm31.Sub(qm31.Mul(carries[i], constScaleCarry), right)
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	finalTerm := qm31.Add(convMod[27], carries[len(carries)-1])
	finalTerm = qm31.Sub(finalTerm, qm31.Mul(constScale256, k))
	finalTerm = qm31.Mul(finalTerm, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, finalTerm)

	return VerifyMul252Result{
		Sum:            sum,
		RangeCheckSums: RangeCheckSums,
	}
}

func convolveLimbs(qm31 *m31.QM31Chip, a, b []m31.QM31) []m31.QM31 {
	res := make([]m31.QM31, len(a)+len(b)-1)
	for i := range res {
		res[i] = qm31.Zero()
	}
	for i := range a {
		for j := range b {
			res[i+j] = qm31.Add(res[i+j], qm31.Mul(a[i], b[j]))
		}
	}
	return res
}

type coeffTerm struct {
	Index int
	Coeff int
}

var verifyMul252ConvCoeff = [][]coeffTerm{
	{{0, 32}, {21, -4}, {49, 8}},
	{{0, 1}, {1, 32}, {22, -4}, {50, 8}},
	{{1, 1}, {2, 32}, {23, -4}, {51, 8}},
	{{2, 1}, {3, 32}, {24, -4}, {52, 8}},
	{{3, 1}, {4, 32}, {25, -4}, {53, 8}},
	{{4, 1}, {5, 32}, {26, -4}, {54, 8}},
	{{5, 1}, {6, 32}, {27, -4}},
	{{0, 2}, {6, 1}, {7, 32}, {28, -4}},
	{{1, 2}, {7, 1}, {8, 32}, {29, -4}},
	{{2, 2}, {8, 1}, {9, 32}, {30, -4}},
	{{3, 2}, {9, 1}, {10, 32}, {31, -4}},
	{{4, 2}, {10, 1}, {11, 32}, {32, -4}},
	{{5, 2}, {11, 1}, {12, 32}, {33, -4}},
	{{6, 2}, {12, 1}, {13, 32}, {34, -4}},
	{{7, 2}, {13, 1}, {14, 32}, {35, -4}},
	{{8, 2}, {14, 1}, {15, 32}, {36, -4}},
	{{9, 2}, {15, 1}, {16, 32}, {37, -4}},
	{{10, 2}, {16, 1}, {17, 32}, {38, -4}},
	{{11, 2}, {17, 1}, {18, 32}, {39, -4}},
	{{12, 2}, {18, 1}, {19, 32}, {40, -4}},
	{{13, 2}, {19, 1}, {20, 32}, {41, -4}},
	{{14, 2}, {20, 1}, {42, -4}, {49, 64}},
	{{15, 2}, {43, -4}, {49, 2}, {50, 64}},
	{{16, 2}, {44, -4}, {50, 2}, {51, 64}},
	{{17, 2}, {45, -4}, {51, 2}, {52, 64}},
	{{18, 2}, {46, -4}, {52, 2}, {53, 64}},
	{{19, 2}, {47, -4}, {53, 2}, {54, 64}},
	{{20, 2}, {48, -4}, {54, 2}},
}

func applyConvModReduction(qm31 *m31.QM31Chip, diff []m31.QM31) []m31.QM31 {
	result := make([]m31.QM31, len(verifyMul252ConvCoeff))
	for i, terms := range verifyMul252ConvCoeff {
		acc := qm31.Zero()
		for _, term := range terms {
			if term.Index >= len(diff) {
				continue
			}
			multiplier := qm31Const(uint64(abs(term.Coeff)))
			value := qm31.Mul(diff[term.Index], multiplier)
			if term.Coeff < 0 {
				acc = qm31.Sub(acc, value)
			} else {
				acc = qm31.Add(acc, value)
			}
		}
		result[i] = acc
	}
	return result
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
