package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type VerifyMulSmallResult struct {
	Sum            m31.QM31
	RangeCheckSums [3]m31.QM31
}

func VerifyMulSmallEvaluate(
	qm31 *m31.QM31Chip,
	aLimbs []m31.QM31,
	bLimbs []m31.QM31,
	cLimbs []m31.QM31,
	carry1 m31.QM31,
	carry3 m31.QM31,
	carry5 m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) VerifyMulSmallResult {
	if len(aLimbs) != 4 || len(bLimbs) != 4 || len(cLimbs) != 8 {
		panic("VerifyMulSmallEvaluate expects 4x4 operands and 8 result limbs")
	}

	const (
		const262144 = 262144
		const512    = 512
	)

	rangeCheck0, err := qm31.Combine(rangeCheckElements, []m31.QM31{carry1})
	if err != nil {
		panic(err)
	}

	const262144QM := qm31Const(const262144)
	const512QM := qm31Const(const512)

	acc := qm31.Sub(qm31.Mul(aLimbs[0], bLimbs[0]), cLimbs[0])
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[0], bLimbs[1]), const512QM))
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[1], bLimbs[0]), const512QM))
	acc = qm31.Sub(acc, qm31.Mul(cLimbs[1], const512QM))

	constraint := qm31.Sub(qm31.Mul(carry1, const262144QM), acc)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	rangeCheck1, err := qm31.Combine(rangeCheckElements, []m31.QM31{carry3})
	if err != nil {
		panic(err)
	}

	acc = carry1
	acc = qm31.Add(acc, qm31.Mul(aLimbs[0], bLimbs[2]))
	acc = qm31.Add(acc, qm31.Mul(aLimbs[1], bLimbs[1]))
	acc = qm31.Add(acc, qm31.Mul(aLimbs[2], bLimbs[0]))
	acc = qm31.Sub(acc, cLimbs[2])
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[0], bLimbs[3]), const512QM))
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[1], bLimbs[2]), const512QM))
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[2], bLimbs[1]), const512QM))
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[3], bLimbs[0]), const512QM))
	acc = qm31.Sub(acc, qm31.Mul(cLimbs[3], const512QM))

	constraint = qm31.Sub(qm31.Mul(carry3, const262144QM), acc)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	rangeCheck2, err := qm31.Combine(rangeCheckElements, []m31.QM31{carry5})
	if err != nil {
		panic(err)
	}

	acc = carry3
	acc = qm31.Add(acc, qm31.Mul(aLimbs[1], bLimbs[3]))
	acc = qm31.Add(acc, qm31.Mul(aLimbs[2], bLimbs[2]))
	acc = qm31.Add(acc, qm31.Mul(aLimbs[3], bLimbs[1]))
	acc = qm31.Sub(acc, cLimbs[4])
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[2], bLimbs[3]), const512QM))
	acc = qm31.Add(acc, qm31.Mul(qm31.Mul(aLimbs[3], bLimbs[2]), const512QM))
	acc = qm31.Sub(acc, qm31.Mul(cLimbs[5], const512QM))

	constraint = qm31.Sub(qm31.Mul(carry5, const262144QM), acc)
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	final := qm31.Sub(qm31.Add(carry5, qm31.Mul(aLimbs[3], bLimbs[3])), qm31.Mul(cLimbs[7], const512QM))
	final = qm31.Sub(final, cLimbs[6])
	final = qm31.Mul(final, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, final)

	return VerifyMulSmallResult{
		Sum: sum,
		RangeCheckSums: [3]m31.QM31{
			rangeCheck0,
			rangeCheck1,
			rangeCheck2,
		},
	}
}
