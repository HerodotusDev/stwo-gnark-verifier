package subroutines

import "github.com/HerodotusDev/stwo-gnark-verifier/m31"

type Sub252Result struct {
	Sum            m31.QM31
	RangeCheckSums [14]m31.QM31
}

func Sub252Evaluate(
	qm31 *m31.QM31Chip,
	cLimbs []m31.QM31,
	aLimbs []m31.QM31,
	resultLimbs []m31.QM31,
	subPBit m31.QM31,
	rangeCheckElements m31.InteractionElements,
	sum m31.QM31,
	domainVanishInv m31.QM31,
	randomCoeff m31.QM31,
) Sub252Result {
	if len(cLimbs) != 28 || len(aLimbs) != 28 || len(resultLimbs) != 28 {
		panic("Sub252Evaluate expects 28 limbs for each operand")
	}

	rcRes := RangeCheckMemValueN28Evaluate(
		qm31,
		resultLimbs,
		rangeCheckElements,
		sum,
		domainVanishInv,
		randomCoeff,
	)
	sum = rcRes.Sum

	sum = VerifyAdd252Evaluate(
		qm31,
		aLimbs,
		resultLimbs,
		cLimbs,
		subPBit,
		sum,
		domainVanishInv,
		randomCoeff,
	)

	return Sub252Result{
		Sum:            sum,
		RangeCheckSums: rcRes.RangeSums14,
	}
}
