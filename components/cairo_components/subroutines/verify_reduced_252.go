package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type VerifyReduced252Result struct {
	Sum            m31.QM31
	RangeCheckSums [2]m31.QM31
}

func VerifyReduced252Evaluate(
	qm31 *m31.QM31Chip,
	limbs []m31.QM31,
	msMax m31.QM31,
	msAndMidMax m31.QM31,
	rcInput m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) VerifyReduced252Result {
	if len(limbs) != 28 {
		panic("VerifyReduced252Evaluate expects 28 limbs")
	}

	one := qm31.One()

	constraint := qm31.Mul(msMax, qm31.Sub(one, msMax))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	constraint = qm31.Mul(msAndMidMax, qm31.Sub(one, msAndMidMax))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	rangeSum0, err := qm31.Combine(
		rangeCheckElements,
		[]m31.QM31{qm31.Sub(limbs[27], msMax)},
	)
	if err != nil {
		panic(err)
	}

	for i := 22; i <= 26; i++ {
		constraint = qm31.Mul(msMax, limbs[i])
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	expected := qm31.Add(qm31Const(120), limbs[21])
	expected = qm31.Sub(expected, msAndMidMax)
	constraint = qm31.Sub(rcInput, qm31.Mul(msMax, expected))
	constraint = qm31.Mul(constraint, domainVanishInv)
	sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)

	rangeSum1, err := qm31.Combine(rangeCheckElements, []m31.QM31{rcInput})
	if err != nil {
		panic(err)
	}

	for i := 0; i <= 20; i++ {
		constraint = qm31.Mul(msAndMidMax, limbs[i])
		constraint = qm31.Mul(constraint, domainVanishInv)
		sum = accumulateConstraint(qm31, sum, randomCoeff, constraint)
	}

	return VerifyReduced252Result{
		Sum: sum,
		RangeCheckSums: [2]m31.QM31{
			rangeSum0,
			rangeSum1,
		},
	}
}
